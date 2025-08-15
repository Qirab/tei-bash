# tei-bash

A bash script for processing TEI P5 XML documents with hierarchical metadata extraction, validation, and XML generation capabilities. Requires Bash 4.0 or higher.

## Usage

```bash
# Read and display metadata
tei.sh --read <file>
tei.sh -r <file>

# Validate TEI P5 compliance
tei.sh --validate <file>
tei.sh -V <file>

# Write TEI XML from command-line terms
tei.sh --write --term "path=value" --output <file>
tei.sh -w -t "fileDesc.titleStmt.title=Example Title" -t "fileDesc.titleStmt.author=John Doe" -o output.xml

# Extract specific hierarchical elements
tei.sh --term <path> <file>
tei.sh -t "fileDesc.titleStmt.title" document.xml
tei.sh -t "persName" document.xml

# Get help
tei.sh --help
```

## Options

- `--read, -r FILE` - Read and display TEI P5 metadata from FILE
- `--validate, -V FILE` - Validate TEI P5 compliance
- `--write, -w [OPTIONS]` - Write TEI XML from command-line terms
- `--term, -t PATH FILE` - Extract specific TEI element or hierarchical path
- `--term, -t "path=value"` - Specify hierarchical path and value (write mode)
- `--output, -o FILE` - Output file for write operations
- `--verbose, -v` - Enable verbose output
- `--debug, -d` - Enable debug output
- `--help, -h` - Display help message

## TEI P5 Hierarchical Paths

### Header Elements
- `fileDesc.titleStmt.title`, `fileDesc.titleStmt.author`, `fileDesc.titleStmt.editor`
- `fileDesc.publicationStmt.publisher`, `fileDesc.publicationStmt.pubPlace`, `fileDesc.publicationStmt.date`
- `fileDesc.sourceDesc.bibl`, `fileDesc.sourceDesc.msDesc`
- `profileDesc.creation`, `profileDesc.langUsage`, `profileDesc.textClass`
- `revisionDesc.change`

### Text Structure
- `text.body.div`, `text.body.div.head`, `text.body.div.p`
- `text.body.div.lg`, `text.body.div.l`, `text.front`, `text.back`

### Named Entities
- `persName` (personal names), `placeName` (place names), `orgName` (organization names)
- `geogName` (geographic names), `date`, `name`

### Critical Apparatus
- `app` (apparatus entry), `lem` (lemma), `rdg` (reading), `wit` (witness), `note`

## Requirements

- Bash 4.0 or higher (uses native associative arrays)
- xmllint (optional, for XML validation)

## About TEI P5

The Text Encoding Initiative XML format is a metadata format defined by the TEI: Guidelines for Electronic Text Encoding and Interchange P5 Version 4.9.0 https://tei-c.org/release/doc/tei-p5-doc/en/html/index.html

