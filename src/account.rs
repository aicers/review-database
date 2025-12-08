use std::{net::IpAddr, num::NonZeroU32};

use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use ring::{
    digest, pbkdf2,
    rand::{self, SecureRandom},
};
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::{UniqueKey, tables::Value};

/// Possible role types of `Account`.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq, Deserialize, Serialize, EnumString)]
pub enum Role {
    #[strum(serialize = "System Administrator")]
    SystemAdministrator,
    #[strum(serialize = "Security Administrator")]
    SecurityAdministrator,
    #[strum(serialize = "Security Manager")]
    SecurityManager,
    #[strum(serialize = "Security Monitor")]
    SecurityMonitor,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct Account {
    pub username: String,
    pub(crate) password: SaltedPassword,
    pub role: Role,
    pub name: String,
    pub department: String,
    pub language: Option<String>,
    pub theme: Option<String>,
    pub(crate) creation_time: DateTime<Utc>,
    pub(crate) last_signin_time: Option<DateTime<Utc>>,
    pub allow_access_from: Option<Vec<IpAddr>>,
    pub max_parallel_sessions: Option<u8>,
    pub(crate) password_hash_algorithm: PasswordHashAlgorithm,
    pub(crate) password_last_modified_at: DateTime<Utc>,
    pub customer_ids: Option<Vec<u32>>,
    pub failed_login_attempts: u8,
    pub locked_out_until: Option<DateTime<Utc>>,
    pub is_suspended: bool,
}

impl Account {
    const DEFAULT_HASH_ALGORITHM: PasswordHashAlgorithm = PasswordHashAlgorithm::Argon2id;

    /// Creates a new `Account` with the given information
    ///
    /// # Errors
    ///
    /// Returns an error if account creation fails.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: &str,
        password: &str,
        role: Role,
        name: String,
        department: String,
        language: Option<String>,
        theme: Option<String>,
        allow_access_from: Option<Vec<IpAddr>>,
        max_parallel_sessions: Option<u8>,
        customer_ids: Option<Vec<u32>>,
    ) -> Result<Self> {
        let password =
            SaltedPassword::new_with_hash_algorithm(password, &Self::DEFAULT_HASH_ALGORITHM)?;
        let now = Utc::now();
        Ok(Self {
            username: username.to_string(),
            password,
            role,
            name,
            department,
            theme,
            language,
            creation_time: now,
            last_signin_time: None,
            allow_access_from,
            max_parallel_sessions,
            password_hash_algorithm: Self::DEFAULT_HASH_ALGORITHM,
            password_last_modified_at: now,
            customer_ids,
            failed_login_attempts: 0,
            locked_out_until: None,
            is_suspended: false,
        })
    }

    /// Update `Account::password` with the given password using
    /// `Account::DEFAULT_HASH_ALGORITHM`.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt for password cannot be generated.
    pub fn update_password(&mut self, password: &str) -> Result<()> {
        self.password =
            SaltedPassword::new_with_hash_algorithm(password, &Self::DEFAULT_HASH_ALGORITHM)?;
        self.password_hash_algorithm = Self::DEFAULT_HASH_ALGORITHM;
        self.password_last_modified_at = Utc::now();
        Ok(())
    }

    #[must_use]
    pub fn verify_password(&self, provided: &str) -> bool {
        self.password.is_match(provided)
    }

    #[must_use]
    pub fn creation_time(&self) -> DateTime<Utc> {
        self.creation_time
    }

    pub fn update_last_signin_time(&mut self) {
        self.last_signin_time = Some(Utc::now());
    }

    /// Resets the last signin time to `None`.
    ///
    /// This is typically used when an administrator resets a user's
    /// password, forcing the user to change their password upon next
    /// sign-in.
    pub fn reset_last_signin_time(&mut self) {
        self.last_signin_time = None;
    }

    #[must_use]
    pub fn last_signin_time(&self) -> Option<DateTime<Utc>> {
        self.last_signin_time
    }

    #[must_use]
    pub fn password_last_modified_at(&self) -> DateTime<Utc> {
        self.password_last_modified_at
    }
}

/// The account security policy.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountPolicy {
    pub expiry_period_in_secs: u32,
    pub lockout_threshold: u32,
    pub lockout_duration_in_secs: u32,
    pub suspension_threshold: u32,
}

impl AccountPolicy {
    /// Validates the account policy values.
    ///
    /// # Errors
    ///
    /// Returns an error if any threshold is zero or if `lockout_threshold`
    /// exceeds `suspension_threshold`.
    pub fn validate(&self) -> Result<()> {
        use anyhow::anyhow;

        if self.expiry_period_in_secs == 0 {
            return Err(anyhow!("expiry period must be greater than 0"));
        }
        if self.lockout_threshold == 0 {
            return Err(anyhow!("lockout threshold must be greater than 0"));
        }
        if self.lockout_duration_in_secs == 0 {
            return Err(anyhow!("lockout duration must be greater than 0"));
        }
        if self.suspension_threshold == 0 {
            return Err(anyhow!("suspension threshold must be greater than 0"));
        }
        if self.lockout_threshold > self.suspension_threshold {
            return Err(anyhow!(
                "lockout threshold cannot be greater than suspension threshold"
            ));
        }
        Ok(())
    }
}

/// Helper struct for updating account policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountPolicyUpdate {
    pub expiry_period_in_secs: Option<u32>,
    pub lockout_threshold: Option<u32>,
    pub lockout_duration_in_secs: Option<u32>,
    pub suspension_threshold: Option<u32>,
}

impl UniqueKey for Account {
    type AsBytes<'a> = &'a [u8];

    fn unique_key(&self) -> Self::AsBytes<'_> {
        self.username.as_bytes()
    }
}

impl Value for Account {
    type AsBytes<'a> = Vec<u8>;

    fn value(&self) -> Vec<u8> {
        use bincode::Options;
        let Ok(value) = bincode::DefaultOptions::new().serialize(&self) else {
            unreachable!("serialization into memory should never fail")
        };
        value
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) enum PasswordHashAlgorithm {
    #[default]
    Pbkdf2HmacSha512 = 0,
    Argon2id = 1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[repr(u32)]
enum HashAlgorithm {
    Sha512 = 0,
    Argon2id,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub(crate) struct SaltedPassword {
    salt: Vec<u8>,
    hash: Vec<u8>,
    algorithm: HashAlgorithm,
    iterations: NonZeroU32,
}

impl SaltedPassword {
    /// Creates a new `SaltedPassword` with the given password and
    /// password hash algorithm to be used.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt cannot be generated.
    pub(crate) fn new_with_hash_algorithm(
        password: &str,
        hash_algorithm: &PasswordHashAlgorithm,
    ) -> Result<Self> {
        match hash_algorithm {
            PasswordHashAlgorithm::Pbkdf2HmacSha512 => Self::with_pbkdf2(password),
            PasswordHashAlgorithm::Argon2id => Self::with_argon2id(password),
        }
    }

    /// Creates a new `SaltedPassword` with the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if the salt cannot be generated.
    fn with_pbkdf2(password: &str) -> Result<Self> {
        // The recommended iteration count for PBKDF2-HMAC-SHA512 is 210,000
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        const ITERATIONS: u32 = 210_000;

        let iterations = NonZeroU32::new(ITERATIONS).expect("valid u32");
        let rng = rand::SystemRandom::new();
        let mut salt = vec![0_u8; digest::SHA512_OUTPUT_LEN];
        rng.fill(&mut salt)?;
        let mut hash = vec![0_u8; digest::SHA512_OUTPUT_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            iterations,
            &salt,
            password.as_bytes(),
            &mut hash,
        );
        Ok(Self {
            salt,
            hash,
            algorithm: HashAlgorithm::Sha512,
            iterations,
        })
    }

    /// Creates a new `SaltedPassword`with argon2id from the given password.
    ///
    /// # Errors
    ///
    /// Returns an error if it fails to compute a password hash from the given
    /// password and salt value.
    fn with_argon2id(password: &str) -> Result<Self> {
        let salt: SaltString = SaltString::generate(&mut OsRng);

        // The default values of the `Argon2` struct are the followings:
        // algorithm: argon2id, version number = 19, memory size = 19456, number of iterations = 2, degree of parallelism = 1
        // This is one of the recommended configuration settings in the OWASP guidelines.
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(Self {
            salt: vec![], // not used in argon2
            hash: password_hash.as_bytes().to_vec(),
            algorithm: HashAlgorithm::Argon2id,
            iterations: NonZeroU32::new(1).expect("non zero u32"), // not used in argon2
        })
    }

    #[must_use]
    fn is_match(&self, password: &str) -> bool {
        match self.algorithm {
            HashAlgorithm::Sha512 => pbkdf2::verify(
                pbkdf2::PBKDF2_HMAC_SHA512,
                self.iterations,
                &self.salt,
                password.as_bytes(),
                &self.hash,
            )
            .is_ok(),
            HashAlgorithm::Argon2id => {
                let hash = String::from_utf8_lossy(&self.hash);
                PasswordHash::new(&hash)
                    .ok()
                    .and_then(|parsed_hash| {
                        Argon2::default()
                            .verify_password(password.as_bytes(), &parsed_hash)
                            .ok()
                    })
                    .is_some()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_test() {
        let password = "password";
        let pbkdf2 = SaltedPassword::with_pbkdf2(password).unwrap();
        assert!(pbkdf2.is_match(password));
    }

    #[test]
    fn argon2id_test() {
        let password = "password";
        let argon2id = SaltedPassword::with_argon2id(password).unwrap();
        assert!(argon2id.is_match(password));
    }

    #[test]
    fn account_password() {
        let account = Account::new(
            "test",
            "password",
            Role::SecurityAdministrator,
            String::new(),
            String::new(),
            None,
            None,
            None,
            None,
            Some(Vec::new()),
        );
        assert!(account.is_ok());

        let account = account.unwrap();
        assert_eq!(
            account.password_hash_algorithm,
            Account::DEFAULT_HASH_ALGORITHM
        );
        let password =
            SaltedPassword::new_with_hash_algorithm("password", &Account::DEFAULT_HASH_ALGORITHM)
                .unwrap();
        assert_eq!(account.password.algorithm, password.algorithm);
    }

    #[test]
    fn account_password_update() {
        let mut account = Account {
            username: "test".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "password",
                &PasswordHashAlgorithm::Pbkdf2HmacSha512,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            department: String::new(),
            name: String::new(),
            language: None,
            theme: None,
            creation_time: Utc::now(),
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Pbkdf2HmacSha512,
            password_last_modified_at: Utc::now(),
            customer_ids: Some(Vec::new()),
            failed_login_attempts: 0,
            locked_out_until: None,
            is_suspended: false,
        };
        assert!(account.verify_password("password"));
        assert!(!account.verify_password("updated"));

        assert!(account.update_password("updated").is_ok());

        assert!(!account.verify_password("password"));
        assert!(account.verify_password("updated"));
        assert_eq!(
            account.password_hash_algorithm,
            Account::DEFAULT_HASH_ALGORITHM
        );
    }

    #[test]
    fn reset_last_signin_time() {
        let mut account = Account::new(
            "test",
            "password",
            Role::SecurityAdministrator,
            String::new(),
            String::new(),
            None,
            None,
            None,
            None,
            Some(Vec::new()),
        )
        .unwrap();

        // Initially, last_signin_time should be None
        assert_eq!(account.last_signin_time(), None);

        // Update last signin time
        account.update_last_signin_time();
        assert!(account.last_signin_time().is_some());

        // Reset last signin time
        account.reset_last_signin_time();
        assert_eq!(account.last_signin_time(), None);
    }
}
