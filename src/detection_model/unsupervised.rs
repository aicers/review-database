//! The completion of the detection model sections of an Unsupervised Engine
//! document: one `[detectors.detection_models.<section>]` table per detection
//! model under each `[[detectors]]` entry, allowed by the clustering model
//! type of the model the detector runs.

use std::ops::Range;

use review_protocol::types::DetectionModel;
use toml_edit::{Array, Document, Item, Table, Value};

use super::{
    ALL_MODELS, CellErrorKind, CellKind, CellSpec, Child, CompletionMode, DETECTION_MODELS,
    DetectionModelsSectionError, DetectorError, IncompleteSection, Node, OperatorValueKind,
    OperatorValueSpec, assignment, check_value, inline_insert, inline_pairs, newline_of,
    properties, section_insert, section_name,
};
use crate::ClusteringModelTypeRef;
use crate::clustering_model_type::clustering_model_type;
use crate::event::LearningMethod;

/// The key of the array of tables holding the detectors.
const DETECTORS: &str = "detectors";

/// The key of the model a detector runs.
const MODEL: &str = "model";

/// Completes the `detection_models` tables of every `[[detectors]]` entry of
/// `document`, as
/// [`complete_engine_document`](super::complete_engine_document) describes
/// for [`AgentKind::Unsupervised`](crate::AgentKind::Unsupervised).
pub(super) fn complete(
    document: &str,
    model_type: &dyn Fn(&str) -> Option<ClusteringModelTypeRef>,
    mode: CompletionMode,
) -> Result<String, DetectionModelsSectionError> {
    let parsed = Document::parse(document)
        .map_err(|e| DetectionModelsSectionError::InvalidToml(e.to_string()))?;
    let detectors = match parsed.as_table().get(DETECTORS) {
        None => return Ok(document.to_owned()),
        Some(Item::ArrayOfTables(detectors)) => detectors,
        Some(Item::Value(Value::Array(array))) if array.is_empty() => {
            return Ok(document.to_owned());
        }
        Some(_) => return Err(DetectionModelsSectionError::DetectorsNotAnArrayOfTables),
    };
    let completion = Completion {
        document,
        newline: newline_of(document),
        mode,
    };
    let mut edits = Edits::default();
    for (index, detector) in detectors.iter().enumerate() {
        completion.detector(index, detector, model_type, &mut edits)?;
    }
    Ok(edits.apply(document))
}

/// Returns the name of the model every `[[detectors]]` entry of `document`
/// runs, in document order, each name once; empty if the document is not
/// valid TOML or has no such entries. An entry whose `model` is not a string
/// names none.
pub(crate) fn detector_models(document: &str) -> Vec<String> {
    let Ok(parsed) = Document::parse(document) else {
        return Vec::new();
    };
    let Some(Item::ArrayOfTables(detectors)) = parsed.as_table().get(DETECTORS) else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for detector in detectors {
        if let Some(Item::Value(Value::String(name))) = detector.get(MODEL)
            && !names.iter().any(|n| n == name.value())
        {
            names.push(name.value().clone());
        }
    }
    names
}

/// Returns the rejection of the detector at `index`, with `error` located
/// within it and the offending value as text where one applies.
fn reject(
    index: usize,
    error: DetectionModelsSectionError,
    value: Option<String>,
) -> DetectionModelsSectionError {
    DetectionModelsSectionError::Detector(Box::new(DetectorError {
        index,
        error,
        value,
    }))
}

/// A section under `detection_models` whose model the detector allows.
struct Kept<'a> {
    name: &'a str,
    node: Node<'a>,
    model: DetectionModel,
    /// The operator values the section lacks, in specification order.
    missing: Vec<&'static OperatorValueSpec>,
    /// The `columns` entries that lack a cell with a default.
    entries: Vec<IncompleteEntry<'a>>,
}

/// An entry of a table-list value that lacks a cell with a default.
struct IncompleteEntry<'a> {
    node: Node<'a>,
    missing: Vec<&'static CellSpec>,
}

/// The document being completed, and how.
struct Completion<'d> {
    document: &'d str,
    newline: &'static str,
    mode: CompletionMode,
}

impl Completion<'_> {
    /// Checks one `[[detectors]]` entry and adds the edits that complete it.
    fn detector(
        &self,
        index: usize,
        detector: &Table,
        model_type: &dyn Fn(&str) -> Option<ClusteringModelTypeRef>,
        edits: &mut Edits,
    ) -> Result<(), DetectionModelsSectionError> {
        let model = match detector.get(MODEL).map(Child::from_item) {
            Some(Child::Value(Value::String(name))) => name.value(),
            other => {
                let value = other.map(|child| self.render(&child));
                return Err(reject(
                    index,
                    DetectionModelsSectionError::ModelNotAString,
                    value,
                ));
            }
        };
        let allowed: &[DetectionModel] = match model_type(model) {
            Some(ClusteringModelTypeRef::Catalog { id, .. }) => {
                clustering_model_type(&id).map_or(&[], |t| t.detection_models)
            }
            Some(ClusteringModelTypeRef::Custom) | None => &[],
        };
        let container = match detector.get(DETECTION_MODELS).map(Child::from_item) {
            None => None,
            Some(Child::Node(node)) => Some(node),
            Some(other) => {
                return Err(reject(
                    index,
                    DetectionModelsSectionError::NotATable,
                    Some(self.render(&other)),
                ));
            }
        };

        let (kept, removed) = self.sections(index, container, allowed)?;
        let missing_models: Vec<DetectionModel> = allowed
            .iter()
            .copied()
            .filter(|m| !kept.iter().any(|k| k.model == *m))
            .collect();

        let Some(container) = container else {
            if !missing_models.is_empty() {
                let (offset, text) = self.headers(&[], &missing_models, detector_end(detector));
                edits.insert(offset, text);
            }
            return Ok(());
        };
        let emptied = kept.is_empty() && missing_models.is_empty();
        match container {
            Node::Inline(table) => {
                let unchanged = removed.is_empty()
                    && missing_models.is_empty()
                    && kept
                        .iter()
                        .all(|k| k.missing.is_empty() && k.entries.is_empty());
                let span = table.span().expect("a parsed inline table has a span");
                if emptied {
                    edits.remove(self.line(&span));
                } else if !unchanged {
                    edits.replace(span, self.render_container(&kept, &missing_models));
                }
            }
            Node::Table(table) => {
                if emptied {
                    self.remove(container, false, edits);
                    return Ok(());
                }
                for node in removed {
                    self.remove(node, false, edits);
                }
                self.fill_table_container(detector, table, &kept, &missing_models, edits);
            }
        }
        Ok(())
    }

    /// Checks the sections of `container`, the detector's `detection_models`
    /// table, and returns those of the models in `allowed`, then those to
    /// remove.
    fn sections<'a>(
        &self,
        index: usize,
        container: Option<Node<'a>>,
        allowed: &[DetectionModel],
    ) -> Result<(Vec<Kept<'a>>, Vec<Node<'a>>), DetectionModelsSectionError> {
        let mut kept = Vec::new();
        let mut removed = Vec::new();
        for (name, child) in container.map_or_default(Node::entries) {
            let Child::Node(node) = child else {
                return Err(reject(
                    index,
                    DetectionModelsSectionError::SectionNotATable {
                        section: name.to_owned(),
                    },
                    Some(self.render(&child)),
                ));
            };
            let section = name.to_owned();
            let refusal = match ALL_MODELS
                .iter()
                .copied()
                .find(|m| section_name(*m) == name)
            {
                None => DetectionModelsSectionError::UnknownModel { section },
                Some(model)
                    if properties(model).learning_method != LearningMethod::Unsupervised =>
                {
                    DetectionModelsSectionError::ModelOfAnotherEngine {
                        section,
                        model_engine: properties(model).learning_method,
                        document_engine: LearningMethod::Unsupervised,
                    }
                }
                Some(model) if !allowed.contains(&model) => {
                    DetectionModelsSectionError::DisallowedModel { section }
                }
                Some(model) => {
                    kept.push(self.check_section(index, name, node, model)?);
                    continue;
                }
            };
            match self.mode {
                CompletionMode::Apply => return Err(reject(index, refusal, None)),
                CompletionMode::Recomplete => removed.push(node),
            }
        }
        Ok((kept, removed))
    }

    /// Checks the section `name` of the allowed `model`, and returns what it
    /// lacks.
    fn check_section<'a>(
        &self,
        index: usize,
        name: &'a str,
        node: Node<'a>,
        model: DetectionModel,
    ) -> Result<Kept<'a>, DetectionModelsSectionError> {
        let specs = properties(model).operator_values;
        let mut entries = Vec::new();
        for (key, child) in node.entries() {
            let Some(spec) = specs.iter().find(|s| s.name == key) else {
                return Err(reject(
                    index,
                    DetectionModelsSectionError::UnknownKey {
                        section: name.to_owned(),
                        key: key.to_owned(),
                    },
                    None,
                ));
            };
            if let Err(error) = check_value(name, spec, &child) {
                let value = self.offending_value(&child, &error);
                return Err(reject(index, error, value));
            }
            if let OperatorValueKind::TableList { cells } = spec.kind {
                for entry in list_entries(&child).into_iter().flatten() {
                    let missing: Vec<_> = cells
                        .iter()
                        .filter(|c| c.kind.has_default() && !entry.contains_key(c.name))
                        .collect();
                    if !missing.is_empty() {
                        entries.push(IncompleteEntry {
                            node: entry,
                            missing,
                        });
                    }
                }
            }
        }
        Ok(Kept {
            name,
            node,
            model,
            missing: specs
                .iter()
                .filter(|spec| !node.contains_key(spec.name))
                .collect(),
            entries,
        })
    }

    /// Adds the edits that fill the kept sections of `container`, a table
    /// written with a header, implicitly or with dotted keys, and add the
    /// sections of `missing_models`.
    fn fill_table_container(
        &self,
        detector: &Table,
        container: &Table,
        kept: &[Kept<'_>],
        missing_models: &[DetectionModel],
        edits: &mut Edits,
    ) {
        let mut headerless = Vec::new();
        for section in kept {
            for entry in &section.entries {
                let lines = entry.missing.iter().map(|cell| cell_assignment(cell));
                let (offset, text) = match entry.node {
                    Node::Inline(table) => inline_insert(self.document, table, lines),
                    Node::Table(table) => self.table_insert(table, entry.node, "", lines),
                };
                edits.insert(offset, text);
            }
            if section.missing.is_empty() {
                continue;
            }
            if matches!(section.node, Node::Table(t) if t.is_implicit() && !t.is_dotted()) {
                headerless.push(section);
                continue;
            }
            let incomplete = IncompleteSection {
                name: section.name,
                node: section.node,
                missing: section.missing.clone(),
            };
            let (offset, text) = section_insert(
                self.document,
                &incomplete,
                container.is_dotted(),
                self.newline,
            );
            edits.insert(offset, text);
        }
        if container.is_dotted() {
            // Sections are added as dotted keys after the last value of
            // `detection_models`, in the detector's body.
            let mut lines = missing_models.iter().flat_map(|m| {
                properties(*m).operator_values.iter().map(|spec| {
                    format!(
                        "{DETECTION_MODELS}.{}.{}",
                        section_name(*m),
                        assignment(spec)
                    )
                })
            });
            let anchor = Node::Table(container)
                .last_value_end()
                .expect("a dotted table has at least one value, each with a span");
            if let Some(first) = lines.next() {
                let (offset, text) = self.lines_after(anchor, std::iter::once(first).chain(lines));
                edits.insert(offset, text);
            }
            if !headerless.is_empty() {
                let (offset, text) = self.headers(&headerless, &[], detector_end(detector));
                edits.insert(offset, text);
            }
        } else if !headerless.is_empty() || !missing_models.is_empty() {
            let (offset, text) = self.headers(&headerless, missing_models, detector_end(detector));
            edits.insert(offset, text);
        }
    }

    /// Returns where and what to insert to add, after the line holding
    /// offset `end`, a section header for each section of `headerless` with
    /// the values it lacks, then one for each model of `missing_models` with
    /// every value at its default.
    fn headers(
        &self,
        headerless: &[&Kept<'_>],
        missing_models: &[DetectionModel],
        end: usize,
    ) -> (usize, String) {
        let sections = headerless
            .iter()
            .map(|k| (key_repr(k.name), k.missing.clone()))
            .chain(missing_models.iter().map(|m| {
                (
                    section_name(*m).to_owned(),
                    properties(*m).operator_values.iter().collect(),
                )
            }));
        let (offset, at_eof) = self.after_line(end);
        let mut text = String::new();
        if at_eof && !self.document.is_empty() && !self.document.ends_with('\n') {
            text.push_str(self.newline);
        }
        for (name, specs) in sections {
            if !self.document.is_empty() || !text.is_empty() {
                text.push_str(self.newline);
            }
            text.push('[');
            text.push_str(DETECTORS);
            text.push('.');
            text.push_str(DETECTION_MODELS);
            text.push('.');
            text.push_str(&name);
            text.push(']');
            text.push_str(self.newline);
            for spec in specs {
                text.push_str(&assignment(spec));
                text.push_str(self.newline);
            }
        }
        (offset, text)
    }

    /// Returns where and what to insert to add `lines`, each prefixed with
    /// `prefix`, at the end of the body of `table`, written with a header.
    fn table_insert(
        &self,
        table: &Table,
        node: Node<'_>,
        prefix: &str,
        lines: impl Iterator<Item = String>,
    ) -> (usize, String) {
        let anchor = node
            .last_value_end()
            .unwrap_or_else(|| table.span().expect("a parsed table header has a span").end);
        self.lines_after(anchor, lines.map(|line| format!("{prefix}{line}")))
    }

    /// Returns where and what to insert to add `lines` after the line
    /// holding offset `anchor`.
    fn lines_after(&self, anchor: usize, lines: impl Iterator<Item = String>) -> (usize, String) {
        let (offset, at_eof) = self.after_line(anchor);
        let mut text = String::new();
        if at_eof {
            text.push_str(self.newline);
        }
        for line in lines {
            text.push_str(&line);
            text.push_str(self.newline);
        }
        (offset, text)
    }

    /// Returns the offset just past the line ending that follows `offset`,
    /// and `false`; or the end of the document and `true` if no line ending
    /// follows.
    fn after_line(&self, offset: usize) -> (usize, bool) {
        match self.document.get(offset..).and_then(|rest| rest.find('\n')) {
            Some(i) => (offset + i + 1, false),
            None => (self.document.len(), true),
        }
    }

    /// Returns the range of the whole lines that hold `span`, with the line
    /// ending of the last.
    fn line(&self, span: &Range<usize>) -> Range<usize> {
        let start = self
            .document
            .get(..span.start)
            .and_then(|before| before.rfind('\n'))
            .map_or(0, |i| i + 1);
        start..self.after_line(span.end).0
    }

    /// Returns the start of the blank lines that directly precede the line
    /// starting at `start`, or `start` if there are none.
    fn blank_lines_before(&self, mut start: usize) -> usize {
        while start > 0 {
            let line_start = self
                .document
                .get(..start - 1)
                .and_then(|before| before.rfind('\n'))
                .map_or(0, |i| i + 1);
            if !self
                .document
                .get(line_start..start)
                .is_some_and(|line| line.trim().is_empty())
            {
                break;
            }
            start = line_start;
        }
        start
    }

    /// Adds the edits that remove every line and header block that writes
    /// `node`, a table under a detector. A header block is removed with the
    /// blank lines directly before its header. `covered` is whether the lines
    /// of `node`'s values are already removed with an enclosing header block.
    fn remove(&self, node: Node<'_>, covered: bool, edits: &mut Edits) {
        let table = match node {
            Node::Inline(table) => {
                if !covered {
                    let span = table.span().expect("a parsed inline table has a span");
                    edits.remove(self.line(&span));
                }
                return;
            }
            Node::Table(table) => table,
        };
        let mut body_covered = covered;
        if !table.is_dotted() {
            body_covered = false;
            if !table.is_implicit() {
                let header = table.span().expect("a parsed table header has a span");
                let end = node.last_value_end().unwrap_or(header.end).max(header.end);
                let lines = self.line(&(header.start..end));
                edits.remove(self.blank_lines_before(lines.start)..lines.end);
                body_covered = true;
            }
        }
        for (_, child) in node.entries() {
            match child {
                Child::Value(value) => {
                    if !body_covered {
                        let span = value.span().expect("a parsed value has a span");
                        edits.remove(self.line(&span));
                    }
                }
                Child::Node(Node::Table(child)) if !child.is_dotted() => {
                    self.remove(Node::Table(child), false, edits);
                }
                Child::Node(child) => self.remove(child, body_covered, edits),
                Child::Tables(tables) => {
                    for table in tables {
                        self.remove(Node::Table(table), false, edits);
                    }
                }
                Child::Other => {}
            }
        }
    }

    /// Returns an inline `detection_models` table holding the kept sections,
    /// completed, then the sections of `missing_models`.
    fn render_container(&self, kept: &[Kept<'_>], missing_models: &[DetectionModel]) -> String {
        let sections = kept
            .iter()
            .map(|section| {
                format!(
                    "{} = {}",
                    key_repr(section.name),
                    self.render_section(section)
                )
            })
            .chain(missing_models.iter().map(|m| {
                let specs: Vec<_> = properties(*m).operator_values.iter().collect();
                format!("{} = {{ {} }}", section_name(*m), inline_pairs(&specs))
            }));
        inline(sections)
    }

    /// Returns a kept section inside an inline `detection_models` table as an
    /// inline table, completed.
    fn render_section(&self, section: &Kept<'_>) -> String {
        let specs = properties(section.model).operator_values;
        let present = section.node.entries().into_iter().map(|(key, child)| {
            let cells = specs.iter().find_map(|spec| match spec.kind {
                OperatorValueKind::TableList { cells } if spec.name == key => Some(cells),
                _ => None,
            });
            let value = match (&child, cells) {
                (Child::Value(Value::Array(items)), Some(cells)) => {
                    let entries: Vec<_> = items
                        .iter()
                        .map(|item| self.render_entry(item, cells))
                        .collect();
                    format!("[{}]", entries.join(", "))
                }
                _ => self.render(&child),
            };
            format!("{} = {value}", key_repr(key))
        });
        inline(present.chain(section.missing.iter().map(|spec| assignment(spec))))
    }

    /// Returns an entry of a table-list value as an inline table, with every
    /// cell of `cells` it lacks that has a default.
    fn render_entry(&self, item: &Value, cells: &[CellSpec]) -> String {
        let Value::InlineTable(table) = item else {
            return self.render(&Child::from_value(item));
        };
        let missing: Vec<_> = cells
            .iter()
            .filter(|c| c.kind.has_default() && !table.contains_key(c.name))
            .collect();
        if missing.is_empty() {
            return self.render(&Child::from_value(item));
        }
        inline(
            Node::Inline(table)
                .entries()
                .into_iter()
                .map(|(k, c)| format!("{} = {}", key_repr(k), self.render(&c)))
                .chain(missing.into_iter().map(cell_assignment)),
        )
    }

    /// Returns the text of a value as the document writes it; a table written
    /// with a header or with dotted keys, and an array of tables, as the
    /// inline table or array of inline tables it equals.
    fn render(&self, child: &Child<'_>) -> String {
        let source = |span: Option<Range<usize>>| span.and_then(|s| self.document.get(s));
        match child {
            Child::Value(value) => source(value.span())
                .map_or_else(|| value.to_string().trim().to_owned(), str::to_owned),
            Child::Node(Node::Inline(table)) => source(table.span())
                .map_or_else(|| table.to_string().trim().to_owned(), str::to_owned),
            Child::Node(node @ Node::Table(_)) => inline(
                node.entries()
                    .into_iter()
                    .map(|(k, c)| format!("{} = {}", key_repr(k), self.render(&c))),
            ),
            Child::Tables(tables) => format!(
                "[{}]",
                tables
                    .iter()
                    .map(|t| self.render(&Child::Node(Node::Table(t))))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Child::Other => String::new(),
        }
    }

    /// Returns the offending value of `error`, a rejection of `child` by
    /// [`check_value`], as text: the value, list entry or cell of the wrong
    /// type, out of range or empty.
    fn offending_value(
        &self,
        child: &Child<'_>,
        error: &DetectionModelsSectionError,
    ) -> Option<String> {
        match error {
            DetectionModelsSectionError::TypeMismatch { .. }
            | DetectionModelsSectionError::OutOfRange { .. } => Some(self.render(child)),
            DetectionModelsSectionError::EntryNotATable { index, .. } => {
                list_item(child, *index).map(|item| self.render(&item))
            }
            DetectionModelsSectionError::Cell(cell) => {
                let entry = list_entries(child).into_iter().nth(cell.index).flatten()?;
                let value = entry
                    .entries()
                    .into_iter()
                    .find(|(name, _)| *name == cell.cell)
                    .map(|(_, value)| value);
                match &cell.kind {
                    CellErrorKind::TypeMismatch { .. } | CellErrorKind::Empty => {
                        value.map(|v| self.render(&v))
                    }
                    CellErrorKind::OutOfRange { value: number, .. } => match value {
                        Some(Child::Value(Value::Array(_))) | None => Some(number.clone()),
                        Some(v) => Some(self.render(&v)),
                    },
                    CellErrorKind::Unknown | CellErrorKind::Missing => None,
                }
            }
            _ => None,
        }
    }
}

/// Returns the entries of a table-list value, each `None` if it is not a
/// table; empty if the value is not a list.
fn list_entries<'a>(child: &Child<'a>) -> Vec<Option<Node<'a>>> {
    match child {
        Child::Value(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::InlineTable(t) => Some(Node::Inline(t)),
                _ => None,
            })
            .collect(),
        Child::Tables(tables) => tables.iter().map(|t| Some(Node::Table(t))).collect(),
        _ => Vec::new(),
    }
}

/// Returns the entry at `index` of a list value.
fn list_item<'a>(child: &Child<'a>, index: usize) -> Option<Child<'a>> {
    match child {
        Child::Value(Value::Array(items)) => items.get(index).map(Child::from_value),
        Child::Tables(tables) => tables.get(index).map(|t| Child::Node(Node::Table(t))),
        _ => None,
    }
}

/// Returns the offset just past the last thing written for `detector`: its
/// header, the values of its body and every table under it.
fn detector_end(detector: &Table) -> usize {
    fn end(node: Node<'_>) -> usize {
        let own = match node {
            Node::Inline(table) => return table.span().map_or(0, |s| s.end),
            Node::Table(table) if !table.is_dotted() && !table.is_implicit() => {
                table.span().map_or(0, |s| s.end)
            }
            Node::Table(_) => 0,
        };
        node.entries()
            .into_iter()
            .map(|(_, child)| match child {
                Child::Value(value) => value.span().map_or(0, |s| s.end),
                Child::Node(node) => end(node),
                Child::Tables(tables) => tables
                    .iter()
                    .map(|t| end(Node::Table(t)))
                    .max()
                    .unwrap_or(0),
                Child::Other => 0,
            })
            .fold(own, usize::max)
    }
    end(Node::Table(detector))
}

/// Returns `name` as a TOML key.
fn key_repr(name: &str) -> String {
    toml_edit::Key::new(name).display_repr().into_owned()
}

/// Returns `pairs` as an inline table.
fn inline(pairs: impl Iterator<Item = String>) -> String {
    let pairs: Vec<_> = pairs.collect();
    if pairs.is_empty() {
        "{}".to_owned()
    } else {
        format!("{{ {} }}", pairs.join(", "))
    }
}

/// Returns `name = default` for a cell with a default.
fn cell_assignment(cell: &CellSpec) -> String {
    let value: Value = match cell.kind {
        CellKind::Bool { default } => default.unwrap_or_default().into(),
        CellKind::Integer { default, .. } => default.unwrap_or_default().into(),
        CellKind::Float { default, .. } => default.unwrap_or_default().into(),
        CellKind::StringList { default } => default
            .unwrap_or_default()
            .iter()
            .copied()
            .collect::<Array>()
            .into(),
        CellKind::IntegerList { default, .. } => default
            .unwrap_or_default()
            .iter()
            .copied()
            .collect::<Array>()
            .into(),
        CellKind::NonEmptyString { default } => default.unwrap_or_default().into(),
    };
    format!("{} = {}", cell.name, value.decorated("", ""))
}

/// Text edits of a document, applied together.
#[derive(Default)]
struct Edits {
    /// Each range of the document to replace, with its replacement. An
    /// insertion has an empty range.
    edits: Vec<(Range<usize>, String)>,
}

impl Edits {
    fn insert(&mut self, offset: usize, text: String) {
        self.edits.push((offset..offset, text));
    }

    fn remove(&mut self, range: Range<usize>) {
        self.edits.push((range, String::new()));
    }

    fn replace(&mut self, range: Range<usize>, text: String) {
        self.edits.push((range, text));
    }

    /// Returns `document` with every edit applied. Edits are applied in
    /// offset order, insertions at one offset in the order they were added
    /// and before a range that starts there; a removed range overlapping one
    /// removed before is removed only past it.
    fn apply(mut self, document: &str) -> String {
        if self.edits.is_empty() {
            return document.to_owned();
        }
        self.edits
            .sort_by_key(|(range, _)| (range.start, !range.is_empty()));
        let mut output = String::with_capacity(document.len());
        let mut copied = 0;
        for (range, text) in self.edits {
            let start = range.start.max(copied);
            output.push_str(document.get(copied..start).unwrap_or_default());
            output.push_str(&text);
            copied = copied.max(range.end);
        }
        output.push_str(document.get(copied..).unwrap_or_default());
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentKind, CellError, CellErrorKind, OperatorValueType, complete_engine_document};

    /// A model of the `http_url` type at its current version.
    const WEB: &str = "web";
    /// A model of the `http_url` type at an earlier version.
    const OLD_WEB: &str = "old-web";
    /// A custom model.
    const CUSTOM: &str = "custom";
    /// A model of a catalog type the catalog does not have.
    const RETIRED: &str = "retired";

    fn types(name: &str) -> Option<ClusteringModelTypeRef> {
        let catalog = |id: &str, version| ClusteringModelTypeRef::Catalog {
            id: id.to_owned(),
            version,
        };
        match name {
            WEB => Some(catalog("http_url", 1)),
            OLD_WEB => Some(catalog("http_url", 0)),
            CUSTOM => Some(ClusteringModelTypeRef::Custom),
            RETIRED => Some(catalog("no_such_type", 1)),
            _ => None,
        }
    }

    fn run(document: &str, mode: CompletionMode) -> Result<String, DetectionModelsSectionError> {
        let output = complete_engine_document(AgentKind::Unsupervised, document, &types, mode);
        if let Ok(output) = &output {
            assert!(Document::parse(output).is_ok(), "invalid output:\n{output}");
            for mode in [CompletionMode::Apply, CompletionMode::Recomplete] {
                assert_eq!(
                    complete_engine_document(AgentKind::Unsupervised, output, &types, mode)
                        .as_deref(),
                    Ok(output.as_str()),
                    "not a fixed point in {mode:?}:\n{output}"
                );
            }
        }
        output
    }

    fn apply(document: &str) -> Result<String, DetectionModelsSectionError> {
        run(document, CompletionMode::Apply)
    }

    fn recomplete(document: &str) -> Result<String, DetectionModelsSectionError> {
        run(document, CompletionMode::Recomplete)
    }

    /// Asserts that both modes complete `document` to `expected`.
    fn both(document: &str, expected: &str) {
        assert_eq!(
            apply(document).as_deref(),
            Ok(expected),
            "apply:\n{document}"
        );
        assert_eq!(
            recomplete(document).as_deref(),
            Ok(expected),
            "recomplete:\n{document}"
        );
    }

    fn detector(model: &str) -> String {
        format!("[[detectors]]\nmodel = \"{model}\"\n")
    }

    const LABEL_DB_MATCH: &str = "[detectors.detection_models.label_db_match]\nenabled = \
                                  true\nevent_range = 100\nmin_events_ratio = 10\ncolumns = []\n";
    const FAR_OUTLIER: &str = "[detectors.detection_models.far_outlier]\nenabled = true\n";

    /// Returns the sections completion adds to an `http_url` detector.
    fn sections() -> String {
        format!("\n{LABEL_DB_MATCH}\n{FAR_OUTLIER}")
    }

    /// The rejection of the detector at `index`.
    fn at(
        index: usize,
        error: DetectionModelsSectionError,
        value: Option<&str>,
    ) -> DetectionModelsSectionError {
        reject(index, error, value.map(str::to_owned))
    }

    fn path(error: &DetectionModelsSectionError) -> String {
        match error {
            DetectionModelsSectionError::Detector(detector) => detector.path(),
            other => panic!("not a detector error: {other:?}"),
        }
    }

    fn cell(
        section: &str,
        key: &str,
        index: usize,
        cell: &str,
        kind: CellErrorKind,
    ) -> DetectionModelsSectionError {
        DetectionModelsSectionError::Cell(Box::new(CellError {
            section: section.to_owned(),
            key: key.to_owned(),
            index,
            cell: cell.to_owned(),
            kind,
        }))
    }

    #[test]
    fn catalog_detector_gets_every_allowed_section_at_its_defaults() {
        for model in [WEB, OLD_WEB] {
            let document = detector(model);
            both(&document, &format!("{document}{}", sections()));
        }
    }

    #[test]
    fn missing_values_and_cells_are_filled_and_present_values_kept() {
        let document = format!(
            "{}[detectors.detection_models.label_db_match]\nenabled = false\nevent_range = 5\n\
             columns = [{{ column_ids = [1], db = \"a\" }}, {{ column_ids = [2], db = \"b\", \
             min_score = 0.5 }}]\n\n[detectors.detection_models.far_outlier]\nenabled = false\n",
            detector(WEB)
        );
        let expected = format!(
            "{}[detectors.detection_models.label_db_match]\nenabled = false\nevent_range = 5\n\
             columns = [{{ column_ids = [1], db = \"a\", min_score = 0.7 }}, {{ column_ids = \
             [2], db = \"b\", min_score = 0.5 }}]\nmin_events_ratio = 10\n\n\
             [detectors.detection_models.far_outlier]\nenabled = false\n",
            detector(WEB)
        );
        both(&document, &expected);

        // Entries as an array of tables, with the section only implicit.
        let document = format!(
            "{}[[detectors.detection_models.label_db_match.columns]]\ncolumn_ids = [1]\ndb = \
             \"a\"\n\n[detectors.detection_models.far_outlier]\nenabled = true\n",
            detector(WEB)
        );
        let expected = format!(
            "{}[[detectors.detection_models.label_db_match.columns]]\ncolumn_ids = [1]\ndb = \
             \"a\"\nmin_score = 0.7\n\n[detectors.detection_models.far_outlier]\nenabled = \
             true\n\n[detectors.detection_models.label_db_match]\nenabled = true\nevent_range = \
             100\nmin_events_ratio = 10\n",
            detector(WEB)
        );
        both(&document, &expected);
    }

    #[test]
    fn sections_follow_the_form_of_detection_models() {
        // Dotted keys in the detector's body.
        let document = format!(
            "{}detection_models.far_outlier.enabled = false\n[detectors.labeldb]\nx = 1\n",
            detector(WEB)
        );
        let expected = format!(
            "{}detection_models.far_outlier.enabled = false\n\
             detection_models.label_db_match.enabled = true\n\
             detection_models.label_db_match.event_range = 100\n\
             detection_models.label_db_match.min_events_ratio = 10\n\
             detection_models.label_db_match.columns = []\n[detectors.labeldb]\nx = 1\n",
            detector(WEB)
        );
        both(&document, &expected);

        // An inline table, written again as a whole.
        let document = format!(
            "{}detection_models = {{ far_outlier = {{}} }} # kept\n",
            detector(WEB)
        );
        let expected = format!(
            "{}detection_models = {{ far_outlier = {{ enabled = true }}, label_db_match = {{ \
             enabled = true, event_range = 100, min_events_ratio = 10, columns = [] }} }} # \
             kept\n",
            detector(WEB)
        );
        both(&document, &expected);

        // A header of its own, with a section in its body.
        let document = format!(
            "{}[detectors.detection_models]\nfar_outlier = {{ enabled = false }}\n",
            detector(WEB)
        );
        both(&document, &format!("{document}\n{LABEL_DB_MATCH}"));
    }

    #[test]
    fn detector_allowing_no_model_has_no_detection_models() {
        for model in [CUSTOM, "missing", RETIRED] {
            let document = format!("{}threshold = 1\n", detector(model));
            both(&document, &document);
            for empty in ["[detectors.detection_models]\n", "detection_models = {}\n"] {
                both(&format!("{document}{empty}"), &document);
            }
        }
    }

    #[test]
    fn only_detectors_allowing_models_get_sections() {
        let custom = format!("{}# a custom model\nthreshold = 1\n", detector(CUSTOM));
        let web = format!("{}threshold = 2\n", detector(WEB));
        let missing = detector("missing");
        let document = format!("{custom}\n{web}\n{missing}");
        let expected = format!("{custom}\n{web}{}\n{missing}", sections());
        both(&document, &expected);
    }

    #[test]
    fn apply_refuses_what_the_type_does_not_allow() {
        use DetectionModelsSectionError::{DisallowedModel, ModelOfAnotherEngine, UnknownModel};

        for model in [CUSTOM, "missing", RETIRED] {
            for section in ["far_outlier", "label_db_match"] {
                let document = format!(
                    "{}[detectors.detection_models.{section}]\nenabled = true\n",
                    detector(model)
                );
                let error = apply(&document).unwrap_err();
                assert_eq!(
                    error,
                    at(
                        0,
                        DisallowedModel {
                            section: section.to_owned()
                        },
                        None
                    )
                );
                assert_eq!(
                    path(&error),
                    format!("detectors[0].detection_models.{section}")
                );
            }
        }
        let document = |section: &str| {
            format!(
                "{}{}[detectors.detection_models.{section}]\nenabled = true\n",
                detector(WEB),
                detector(WEB)
            )
        };
        assert_eq!(
            apply(&document("no_such_model")),
            Err(at(
                1,
                UnknownModel {
                    section: "no_such_model".to_owned()
                },
                None
            ))
        );
        assert_eq!(
            apply(&document("port_scan")),
            Err(at(
                1,
                ModelOfAnotherEngine {
                    section: "port_scan".to_owned(),
                    model_engine: LearningMethod::SemiSupervised,
                    document_engine: LearningMethod::Unsupervised,
                },
                None
            ))
        );
    }

    #[test]
    fn recomplete_removes_what_the_type_does_not_allow_and_fills_the_rest() {
        // Every form of a section to remove, with an emptied table removed.
        let kept = "# kept\n[detectors.labeldb]\nx = 1\n";
        for removed in [
            "[detectors.detection_models.far_outlier]\nenabled = true\n\
             [detectors.detection_models.label_db_match]\nevent_range = 5\n\
             [[detectors.detection_models.label_db_match.columns]]\ncolumn_ids = [1]\ndb = \
             \"a\"\n",
            "[detectors.detection_models]\nfar_outlier.enabled = true\nport_scan = {}\n",
            "detection_models.far_outlier.enabled = true\ndetection_models.no_such_model = {}\n",
            "detection_models = { far_outlier = { enabled = 1 } }\n",
        ] {
            let document = format!("{}{removed}{kept}", detector(CUSTOM));
            assert!(apply(&document).is_err());
            assert_eq!(
                recomplete(&document),
                Ok(format!("{}{kept}", detector(CUSTOM))),
                "{document}"
            );
        }

        // Disallowed sections removed and allowed ones filled in one call.
        let document = format!(
            "{}[detectors.detection_models.port_scan]\nenabled = true\n\
             [detectors.detection_models.far_outlier]\nenabled = false\n",
            detector(WEB)
        );
        assert_eq!(
            recomplete(&document),
            Ok(format!(
                "{}[detectors.detection_models.far_outlier]\nenabled = false\n\n{LABEL_DB_MATCH}",
                detector(WEB)
            ))
        );
        let document = format!(
            "{}detection_models = {{ port_scan = {{ enabled = true }}, far_outlier.enabled = \
             false, label_db_match = {{ columns = [{{ column_ids = [1], db = \"a\" }}] }} }}\n",
            detector(WEB)
        );
        assert_eq!(
            recomplete(&document),
            Ok(format!(
                "{}detection_models = {{ far_outlier = {{ enabled = false }}, label_db_match = \
                 {{ columns = [{{ column_ids = [1], db = \"a\", min_score = 0.7 }}], enabled = \
                 true, event_range = 100, min_events_ratio = 10 }} }}\n",
                detector(WEB)
            ))
        );
    }

    #[test]
    fn recomplete_returns_any_other_error() {
        let disallowed = format!(
            "{}[detectors.detection_models.far_outlier]\nenabled = true\n",
            detector(CUSTOM)
        );
        let invalid = format!(
            "{}[detectors.detection_models.far_outlier]\nenabled = 1\n",
            detector(WEB)
        );
        let mismatch = at(
            1,
            DetectionModelsSectionError::TypeMismatch {
                section: "far_outlier".to_owned(),
                key: "enabled".to_owned(),
                expected: OperatorValueType::Bool,
            },
            Some("1"),
        );
        assert_eq!(
            recomplete(&format!("{disallowed}{invalid}")),
            Err(mismatch.clone())
        );
        // In the same detector as the section to remove.
        let document = format!(
            "{}[detectors.detection_models.port_scan]\nenabled = true\n\
             [detectors.detection_models.far_outlier]\nenabled = 1\n",
            detector(WEB)
        );
        assert_eq!(
            recomplete(&document),
            Err(at(
                0,
                DetectionModelsSectionError::TypeMismatch {
                    section: "far_outlier".to_owned(),
                    key: "enabled".to_owned(),
                    expected: OperatorValueType::Bool,
                },
                Some("1"),
            ))
        );
    }

    /// Completes a `label_db_match` section with `body` on an `http_url`
    /// detector.
    fn label_db_match(body: &str) -> Result<String, DetectionModelsSectionError> {
        apply(&format!(
            "{}[detectors.detection_models.label_db_match]\n{body}\n",
            detector(WEB)
        ))
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn ranges_are_accepted_at_their_limits_and_refused_past_them() {
        let columns = |cells: &str| format!("columns = [{{ {cells} }}]");
        for body in [
            "event_range = 1".to_owned(),
            "event_range = 100".to_owned(),
            "min_events_ratio = 0".to_owned(),
            "min_events_ratio = 100".to_owned(),
            columns("column_ids = [0], db = \"a\""),
            columns(&format!("column_ids = [{}], db = \"a\"", i64::MAX)),
            columns("column_ids = [1], db = \"a\", min_score = 1.0"),
            columns("column_ids = [1], db = \"a\", min_score = 5e-324"),
        ] {
            assert!(label_db_match(&body).is_ok(), "{body}");
        }
        let out_of_range = |key: &str, value: &str, min: &str, max: &str| {
            at(
                0,
                DetectionModelsSectionError::OutOfRange {
                    section: "label_db_match".to_owned(),
                    key: key.to_owned(),
                    value: value.to_owned(),
                    min: min.to_owned(),
                    max: max.to_owned(),
                },
                Some(value),
            )
        };
        for (body, error) in [
            (
                "event_range = 0",
                out_of_range("event_range", "0", "1", "100"),
            ),
            (
                "event_range = 101",
                out_of_range("event_range", "101", "1", "100"),
            ),
            (
                "min_events_ratio = -1",
                out_of_range("min_events_ratio", "-1", "0", "100"),
            ),
            (
                "min_events_ratio = 101",
                out_of_range("min_events_ratio", "101", "0", "100"),
            ),
        ] {
            assert_eq!(label_db_match(body), Err(error), "{body}");
        }
        let cell_range = |name: &str, value: &str, min: &str, max: &str| {
            at(
                0,
                cell(
                    "label_db_match",
                    "columns",
                    0,
                    name,
                    CellErrorKind::OutOfRange {
                        value: value.to_owned(),
                        min: min.to_owned(),
                        max: max.to_owned(),
                    },
                ),
                Some(value),
            )
        };
        let max = i64::MAX.to_string();
        for (cells, error) in [
            (
                "column_ids = [1, -1], db = \"a\"",
                cell_range("column_ids", "-1", "0", &max),
            ),
            (
                "column_ids = [1], db = \"a\", min_score = 0.0",
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        0,
                        "min_score",
                        CellErrorKind::OutOfRange {
                            value: "0".to_owned(),
                            min: "0 (exclusive)".to_owned(),
                            max: "1".to_owned(),
                        },
                    ),
                    Some("0.0"),
                ),
            ),
            (
                "column_ids = [1], db = \"a\", min_score = 1.0000001",
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        0,
                        "min_score",
                        CellErrorKind::OutOfRange {
                            value: "1.0000001".to_owned(),
                            min: "0 (exclusive)".to_owned(),
                            max: "1".to_owned(),
                        },
                    ),
                    Some("1.0000001"),
                ),
            ),
        ] {
            assert_eq!(label_db_match(&columns(cells)), Err(error), "{cells}");
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_case_of_the_error_contract() {
        use DetectionModelsSectionError as E;

        let section = |s: &str| s.to_owned();
        let web = detector(WEB);
        let lmd = "[detectors.detection_models.label_db_match]";
        // (document, error, path)
        let cases: Vec<(String, E, &str)> = vec![
            (
                format!("{web}model2 = 1\nmodel = 1\n").replacen("model = \"web\"\n", "", 1),
                at(0, E::ModelNotAString, Some("1")),
                "detectors[0].model",
            ),
            (
                "[[detectors]]\nthreshold = 1\n".to_owned(),
                at(0, E::ModelNotAString, None),
                "detectors[0].model",
            ),
            (
                format!("{web}detection_models = 1\n"),
                at(0, E::NotATable, Some("1")),
                "detectors[0].detection_models",
            ),
            (
                format!("{web}detection_models.far_outlier = \"on\"\n"),
                at(
                    0,
                    E::SectionNotATable {
                        section: section("far_outlier"),
                    },
                    Some("\"on\""),
                ),
                "detectors[0].detection_models.far_outlier",
            ),
            (
                format!("{web}{lmd}\ncolumns = 1\n"),
                at(
                    0,
                    E::TypeMismatch {
                        section: section("label_db_match"),
                        key: "columns".to_owned(),
                        expected: OperatorValueType::TableList,
                    },
                    Some("1"),
                ),
                "detectors[0].detection_models.label_db_match.columns",
            ),
            (
                format!("{web}{lmd}\ncolumns = [{{ column_ids = [1], db = \"a\" }}, 2]\n"),
                at(
                    0,
                    E::EntryNotATable {
                        section: section("label_db_match"),
                        key: "columns".to_owned(),
                        index: 1,
                    },
                    Some("2"),
                ),
                "detectors[0].detection_models.label_db_match.columns[1]",
            ),
            (
                format!(
                    "{web}{lmd}\ncolumns = [{{ column_ids = [1], db = \"a\" }}, {{ column_ids = [1], db = 3 }}]\n"
                ),
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        1,
                        "db",
                        CellErrorKind::TypeMismatch {
                            expected: OperatorValueType::NonEmptyString,
                        },
                    ),
                    Some("3"),
                ),
                "detectors[0].detection_models.label_db_match.columns[1].db",
            ),
            (
                format!("{web}{lmd}\nthreshold = 1\n"),
                at(
                    0,
                    E::UnknownKey {
                        section: section("label_db_match"),
                        key: "threshold".to_owned(),
                    },
                    None,
                ),
                "detectors[0].detection_models.label_db_match.threshold",
            ),
            (
                format!("{web}{lmd}\ncolumns = [{{ column_ids = [1], db = \"a\", weight = 1 }}]\n"),
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        0,
                        "weight",
                        CellErrorKind::Unknown,
                    ),
                    None,
                ),
                "detectors[0].detection_models.label_db_match.columns[0].weight",
            ),
            (
                format!("{web}{lmd}\ncolumns = [{{ db = \"a\" }}]\n"),
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        0,
                        "column_ids",
                        CellErrorKind::Missing,
                    ),
                    None,
                ),
                "detectors[0].detection_models.label_db_match.columns[0].column_ids",
            ),
            (
                format!(
                    "{web}[[detectors.detection_models.label_db_match.columns]]\ncolumn_ids = [1]\n"
                ),
                at(
                    0,
                    cell("label_db_match", "columns", 0, "db", CellErrorKind::Missing),
                    None,
                ),
                "detectors[0].detection_models.label_db_match.columns[0].db",
            ),
            (
                format!("{web}{lmd}\ncolumns = [{{ column_ids = [], db = \"a\" }}]\n"),
                at(
                    0,
                    cell(
                        "label_db_match",
                        "columns",
                        0,
                        "column_ids",
                        CellErrorKind::Empty,
                    ),
                    Some("[]"),
                ),
                "detectors[0].detection_models.label_db_match.columns[0].column_ids",
            ),
            (
                format!("{web}{lmd}\ncolumns = [{{ column_ids = [1], db = \"\" }}]\n"),
                at(
                    0,
                    cell("label_db_match", "columns", 0, "db", CellErrorKind::Empty),
                    Some("\"\""),
                ),
                "detectors[0].detection_models.label_db_match.columns[0].db",
            ),
            (
                format!("{web}[detectors.detection_models.far_outlier.enabled]\nx = 1\n"),
                at(
                    0,
                    E::TypeMismatch {
                        section: section("far_outlier"),
                        key: "enabled".to_owned(),
                        expected: OperatorValueType::Bool,
                    },
                    Some("{ x = 1 }"),
                ),
                "detectors[0].detection_models.far_outlier.enabled",
            ),
        ];
        for (document, error, expected_path) in cases {
            for mode in [CompletionMode::Apply, CompletionMode::Recomplete] {
                assert_eq!(run(&document, mode), Err(error.clone()), "{document}");
            }
            assert_eq!(path(&error), expected_path);
        }

        assert!(matches!(apply("not [valid toml"), Err(E::InvalidToml(_))));
        for document in [
            "detectors = 1\n",
            "detectors = [{ model = \"web\" }]\n",
            "[detectors]\nmodel = \"web\"\n",
        ] {
            for mode in [CompletionMode::Apply, CompletionMode::Recomplete] {
                assert_eq!(run(document, mode), Err(E::DetectorsNotAnArrayOfTables));
            }
        }
    }

    #[test]
    fn error_messages_name_the_detector_and_the_value() {
        let error = apply(&format!(
            "{}{}[detectors.detection_models.far_outlier]\nenabled = \"yes\"\n",
            detector(WEB),
            detector(WEB)
        ))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "`detectors[1]`: `detection_models.far_outlier.enabled` must be a boolean (found \
             `\"yes\"`)"
        );
        let error = apply(&format!(
            "{}[detectors.detection_models.far_outlier]\n",
            detector(CUSTOM)
        ))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("`detectors[0]`: `detection_models.far_outlier`")
        );
    }

    #[test]
    fn everything_outside_detection_models_is_kept_byte_for_byte() {
        let document = "# head comment\r\ntitle = 'x'  # trailing\r\n\r\n[[detectors]]\r\nid = \
                        1\r\nmodel = \"custom\"\r\n[detectors.detection_models.far_outlier]\r\n\
                        enabled = true\r\n\r\n[detectors.labeldb]\r\nrules = [ 1,2 ]\r\n\r\n\
                        [[detectors]]\r\nmodel   =   \"web\"\r\n[detectors.labeldb]\r\nrules = \
                        []\r\n[other]\r\nkey = \"\"\"\r\nmulti\r\n\"\"\"";
        let expected = "# head comment\r\ntitle = 'x'  # trailing\r\n\r\n[[detectors]]\r\nid = \
                        1\r\nmodel = \"custom\"\r\n\r\n[detectors.labeldb]\r\nrules = [ 1,2 \
                        ]\r\n\r\n[[detectors]]\r\nmodel   =   \"web\"\r\n[detectors.labeldb]\r\n\
                        rules = []\r\n\r\n[detectors.detection_models.label_db_match]\r\n\
                        enabled = true\r\nevent_range = 100\r\nmin_events_ratio = 10\r\ncolumns \
                        = []\r\n\r\n[detectors.detection_models.far_outlier]\r\nenabled = \
                        true\r\n[other]\r\nkey = \"\"\"\r\nmulti\r\n\"\"\"";
        assert_eq!(recomplete(document).as_deref(), Ok(expected));

        // No trailing line ending.
        let document = "[[detectors]]\nmodel = \"web\"";
        both(document, &format!("{document}\n{}", sections()));
    }

    #[test]
    fn documents_without_detectors_are_returned_unchanged() {
        for document in ["", "threshold = 1\n", "detectors = []\n", "# only\n"] {
            both(document, document);
        }
    }

    #[test]
    fn detector_models_lists_each_named_model_once() {
        let document = format!(
            "{}{}{}[[detectors]]\nmodel = 1\n",
            detector("b"),
            detector("a"),
            detector("b")
        );
        assert_eq!(detector_models(&document), ["b", "a"]);
        assert_eq!(detector_models("not [toml"), Vec::<String>::new());
        assert_eq!(detector_models("detectors = 1"), Vec::<String>::new());
    }
}
