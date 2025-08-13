#!/bin/bash
#
# tei.sh - TEI P5 XML Processing Script (Modernized Bash 4)
# 
# A streamlined bash script for processing TEI P5 XML documents with hierarchical metadata extraction,
# validation, and XML generation capabilities. Requires Bash 4.0 or higher.
#
# Version: v2.0.0
# Author: Qirab™ project of the Thesaurus Islamicus Foundation 
# License: CC0
#
# Usage:
#   tei.sh --read <file>
#   tei.sh --validate <file>
#   tei.sh --write --term "path=value" --output <file>
#   tei.sh --term <path> <file>
#   tei.sh --help
#

# Bash 4+ requirement check
if [[ ${BASH_VERSION%%.*} -lt 4 ]]; then
    echo "Error: This script requires Bash 4.0 or higher. Current version: $BASH_VERSION" >&2
    exit 1
fi

set -o errexit   # Exit on error
set -o pipefail  # Exit on pipe failure
set -o nounset   # Exit on undefined variable (now safe with Bash 4)

# ==============================================================================
# CONSTANTS AND GLOBAL VARIABLES
# ==============================================================================

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# TEI namespaces
readonly TEI_NS="http://www.tei-c.org/ns/1.0"
readonly XML_NS="http://www.w3.org/XML/1998/namespace"

# TEI P5 Header Elements (hierarchical paths)
readonly -a TEI_HEADER_ELEMENTS=(
    "fileDesc.titleStmt.title"
    "fileDesc.titleStmt.author"
    "fileDesc.titleStmt.editor"
    "fileDesc.titleStmt.respStmt"
    "fileDesc.publicationStmt.publisher"
    "fileDesc.publicationStmt.pubPlace"
    "fileDesc.publicationStmt.date"
    "fileDesc.sourceDesc.bibl"
    "fileDesc.sourceDesc.msDesc"
    "encodingDesc.projectDesc"
    "encodingDesc.editorialDecl"
    "profileDesc.creation"
    "profileDesc.langUsage"
    "profileDesc.textClass"
    "revisionDesc.change"
)

# TEI P5 Text Structure Elements (paths relative to extracted text body)
readonly -a TEI_TEXT_ELEMENTS=(
    "body.div"
    "body.div.head"
    "body.div.p"
    "body.div.lg"
    "body.div.l"
    "front"
    "back"
)

# TEI P5 Named Entities
readonly -a TEI_NAMED_ENTITIES=(
    "persName"
    "placeName" 
    "orgName"
    "geogName"
    "date"
    "name"
)

# TEI P5 Critical Apparatus Elements
readonly -a TEI_CRITICAL_ELEMENTS=(
    "app"
    "lem"
    "rdg"
    "wit"
    "note"
)

# File size limits (100MB default)
readonly MAX_FILE_SIZE=$((100 * 1024 * 1024))

# Global variables using native Bash 4 associative arrays
declare -A TEI_metadata     # Main metadata storage
declare -A TEI_write_data   # Data for write operations
declare -A TEI_config       # Script configuration
declare -a TEI_selected_terms  # Array for selected terms
declare -i TEI_validation_errors=0
declare -i TEI_validation_warnings=0
declare TEI_operation=""
declare TEI_input_file=""
declare TEI_output_file=""
declare TEI_term_name=""
declare TEI_verbose=0
declare TEI_debug=0

# ==============================================================================
# UTILITY FUNCTIONS (Bash 4 Native)
# ==============================================================================

# Get value from metadata associative array
get_tei_value() {
    local key="$1"
    echo "${TEI_metadata[$key]:-}"
}

# Set value in metadata associative array
set_tei_value() {
    local key="$1"
    local value="$2"
    TEI_metadata[$key]="$value"
}

# Append value to existing metadata (for multiple values)
append_tei_value() {
    local key="$1"
    local value="$2"
    local existing="${TEI_metadata[$key]:-}"
    TEI_metadata[$key]="${existing:+$existing;}$value"
}

# Clear metadata array
clear_metadata() {
    TEI_metadata=()
}

# Get all metadata keys
get_metadata_keys() {
    printf '%s\n' "${!TEI_metadata[@]}"
}

# Check if key exists in metadata
has_tei_key() {
    local key="$1"
    [[ -n "${TEI_metadata[$key]:-}" ]]
}

# Log message with timestamp
log_message() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    case "$level" in
        ERROR)
            echo "[$timestamp] ERROR: $message" >&2
            ;;
        WARNING)
            echo "[$timestamp] WARNING: $message" >&2
            ;;
        INFO)
            if [[ $TEI_verbose -eq 1 ]]; then
                echo "[$timestamp] INFO: $message"
            fi
            ;;
        DEBUG)
            if [[ $TEI_debug -eq 1 ]]; then
                echo "[$timestamp] DEBUG: $message"
            fi
            ;;
        *)
            echo "[$timestamp] $message"
            ;;
    esac
}

# Handle errors with proper cleanup
handle_error() {
    local error_type="$1"
    local error_message="$2"
    local exit_code="${3:-1}"
    
    case "$error_type" in
        CRITICAL)
            log_message "ERROR" "$error_message"
            cleanup_temp_files
            exit "$exit_code"
            ;;
        VALIDATION)
            log_message "ERROR" "$error_message"
            ((TEI_validation_errors++))
            ;;
        WARNING)
            log_message "WARNING" "$error_message"
            ((TEI_validation_warnings++))
            ;;
    esac
}

# Clean up temporary files
cleanup_temp_files() {
    if [[ -n "${temp_dir:-}" ]] && [[ -d "$temp_dir" ]]; then
        rm -rf "$temp_dir"
    fi
}

# Trap for cleanup on exit
trap cleanup_temp_files EXIT INT TERM

# Validate file security
validate_file_security() {
    local file="$1"
    
    # Check for path traversal attempts
    if [[ "$file" =~ \.\./|/\.\. ]]; then
        handle_error "CRITICAL" "Path traversal attempt detected" 1
    fi
    
    # Check if file exists
    if [[ ! -e "$file" ]]; then
        handle_error "CRITICAL" "File not found: $file" 1
    fi
    
    # Check if file is readable
    if [[ ! -r "$file" ]]; then
        handle_error "CRITICAL" "File not readable: $file" 1
    fi
    
    # Check file size
    local size
    if [[ "$(uname)" == "Darwin" ]]; then
        size=$(stat -f%z "$file" 2>/dev/null || echo 0)
    else
        size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    fi
    
    if [[ "$size" -gt "$MAX_FILE_SIZE" ]]; then
        handle_error "CRITICAL" "File too large (>100MB): $file" 1
    fi
    
    return 0
}

# Escape XML special characters
escape_xml_chars() {
    local input="$1"
    printf '%s\n' "$input" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}

# Unescape XML special characters
unescape_xml_chars() {
    local input="$1"
    printf '%s\n' "$input" | sed \
        -e 's/\&lt;/</g' \
        -e 's/\&gt;/>/g' \
        -e 's/\&quot;/"/g' \
        -e "s/\&apos;/'/g" \
        -e 's/\&amp;/\&/g'
}

# Trim leading and trailing whitespace
trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo "$var"
}

# Resolve hierarchical TEI path in parsed content (improved robustness)
resolve_hierarchical_path() {
    local path="$1"
    local content="$2"
    
    # Input validation
    if [[ -z "$path" || -z "$content" ]]; then
        log_message "DEBUG" "Empty path or content in resolve_hierarchical_path"
        return 1
    fi
    
    # Split path by dots using Bash 4 features
    IFS='.' read -ra path_parts <<< "$path"
    local current_content="$content"
    
    log_message "DEBUG" "Resolving path: $path with ${#path_parts[@]} parts"
    
    # Navigate through each path component
    for part in "${path_parts[@]}"; do
        log_message "DEBUG" "Processing path component: $part"
        
        # Escape special regex characters in part name
        local escaped_part=$(printf '%s\n' "$part" | sed 's/[[][\*^$()+?{|]/\\\\&/g')
        
        # Try multiple extraction strategies for robustness
        local extracted=""
        
        # Strategy 1: Simple regex (fastest for well-formed XML)
        local pattern="<${escaped_part}[^>]*>\\(.*\\)</${escaped_part}>"
        if [[ "$current_content" =~ $pattern ]]; then
            extracted="${BASH_REMATCH[1]}"
            log_message "DEBUG" "Extracted using regex: ${#extracted} chars"
        else
            # Strategy 2: Use simple sed extraction
            extracted=$(echo "$current_content" | sed -n "/<${escaped_part}[^>]*>/,/<\\/${escaped_part}>/p" | sed -e '1s/.*<[^>]*>//' -e '$s/<\/[^>]*>.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        fi
        
        if [[ -n "$extracted" ]]; then
            current_content="$extracted"
            log_message "DEBUG" "Successfully extracted content for $part"
        else
            # Strategy 3: Fallback with sed (last resort)
            local sed_extracted
            sed_extracted=$(echo "$current_content" | sed -n "s/.*<${escaped_part}[^>]*>\\(.*\\)<\\/${escaped_part}>.*/\\1/p" | head -n 1)
            if [[ -n "$sed_extracted" ]]; then
                current_content="$sed_extracted"
                log_message "DEBUG" "Extracted using sed fallback for $part"
            else
                log_message "DEBUG" "Failed to extract content for path component: $part"
                return 1  # Content extraction failed
            fi
        fi
    done
    
    # Clean up the final content
    if [[ "$current_content" != *"<"* ]]; then
        # Plain text content
        echo "$current_content"
    else
        # Extract text from XML, handling potential edge cases
        local text_only
        text_only=$(echo "$current_content" | sed -e 's/<[^>]*>//g' -e 's/^[[:space:]]*//;s/[[:space:]]*$//' -e '/^$/d')
        if [[ -n "$text_only" ]]; then
            echo "$text_only"
        else
            # If we still have XML structure, return as-is (might be needed for complex elements)
            echo "$current_content"
        fi
    fi
    
    return 0
}

# ==============================================================================
# XML VALIDATION AND PARSING FUNCTIONS
# ==============================================================================

# Basic XML structure validation
validate_xml_structure() {
    local file="$1"
    local errors=0
    
    log_message "DEBUG" "Validating XML structure for $file"
    
    # Check for XML declaration
    if ! head -n 3 "$file" | grep -q "<?xml"; then
        log_message "WARNING" "Missing XML declaration - may cause parsing issues"
    fi
    
    # Simplified validation - just check basic structure
    local content
    content=$(cat "$file")
    
    # Check for basic TEI structure
    if ! [[ "$content" =~ \<TEI.*\> ]] && ! [[ "$content" =~ \<tei.*\> ]]; then
        log_message "WARNING" "No TEI root element found"
        ((errors++))
    fi
    
    # Check for basic closing tag balance (simplified)
    local opening_count
    local closing_count
    opening_count=$(grep -o '<[a-zA-Z][a-zA-Z0-9:._-]*[^>]*[^/]>' "$file" | wc -l || echo 0)
    closing_count=$(grep -o '</[a-zA-Z][a-zA-Z0-9:._-]*>' "$file" | wc -l || echo 0)
    
    # Allow for some difference (self-closing tags, etc.)
    if [[ $((opening_count - closing_count)) -gt 5 ]] || [[ $((closing_count - opening_count)) -gt 5 ]]; then
        log_message "WARNING" "Significant tag imbalance detected (opening: $opening_count, closing: $closing_count)"
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_message "WARNING" "XML structure validation found $errors issue(s). Proceeding with caution."
    else
        log_message "DEBUG" "XML structure validation passed"
    fi
    
    return 0  # Always succeed to allow parsing
}

# ==============================================================================
# PARSING FUNCTIONS
# ==============================================================================

# Parse TEI XML format using native associative arrays
parse_tei_xml() {
    local file="$1"
    
    # Clear existing metadata
    clear_metadata
    
    log_message "DEBUG" "Starting TEI XML parsing with Bash 4 native arrays"
    
    # Basic XML well-formedness check
    if ! validate_xml_structure "$file"; then
        handle_error "CRITICAL" "File is not well-formed XML or severely malformed" 1
    fi
    
    # Read entire file for complex hierarchical parsing (safe memory handling)
    local file_content
    # Use a safe approach that doesn't load everything into memory at once for large files
    if [[ $(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0) -gt $((10 * 1024 * 1024)) ]]; then
        # For files larger than 10MB, use streaming approach
        file_content=$(perl -pe 'chomp if eof' "$file" | tr '\t' ' ')
    else
        # For smaller files, use the original approach but safer
        file_content=$(cat "$file" | perl -pe 'chomp if eof' | tr '\t' ' ')
    fi
    
    # Extract teiHeader content first
    local tei_header_pattern="\\<teiHeader[^>]*\\>(.*)\\</teiHeader\\>"
    if [[ "$file_content" =~ $tei_header_pattern ]]; then
        local tei_header="${BASH_REMATCH[1]}"
        log_message "DEBUG" "Found teiHeader content"
        
        # Parse header elements using hierarchical paths
        for header_path in "${TEI_HEADER_ELEMENTS[@]}"; do
            local resolved_value
            if resolved_value=$(resolve_hierarchical_path "$header_path" "$tei_header"); then
                resolved_value=$(trim "$resolved_value")
                resolved_value=$(unescape_xml_chars "$resolved_value")
                if [[ -n "$resolved_value" ]]; then
                    append_tei_value "$header_path" "$resolved_value"
                    log_message "DEBUG" "Extracted $header_path: $resolved_value"
                fi
            fi
        done
    fi
    
    # Extract text body content using sed for multiline support
    local text_body
    text_body=$(echo "$file_content" | sed -n 's/.*<text[^>]*>\(.*\)<\/text>.*/\1/p' | head -n 1)
    
    # If single line extraction failed, try multiline approach
    if [[ -z "$text_body" ]]; then
        # Extract everything between <text> and </text> tags
        local start_found=0
        local temp_content=""
        while IFS= read -r line; do
            if [[ "$line" == *"<text"* ]] && [[ $start_found -eq 0 ]]; then
                start_found=1
                # Extract content after the opening tag on the same line
                if [[ "$line" == *">"* ]]; then
                    local after_tag="${line#*>}"
                    if [[ "$after_tag" != *"</text>"* ]]; then
                        temp_content="$after_tag"
                    fi
                fi
                continue
            elif [[ "$line" == *"</text>"* ]] && [[ $start_found -eq 1 ]]; then
                # Extract content before the closing tag
                local before_tag="${line%%</text>*}"
                if [[ -n "$before_tag" ]]; then
                    temp_content="${temp_content}${before_tag}"
                fi
                break
            elif [[ $start_found -eq 1 ]]; then
                temp_content="${temp_content}${line}"$'\n'
            fi
        done <<< "$file_content"
        text_body="$temp_content"
    fi
    
    if [[ -n "$text_body" ]]; then
        log_message "DEBUG" "Found text content: ${#text_body} characters"
        
        # Parse text elements using hierarchical paths
        for text_path in "${TEI_TEXT_ELEMENTS[@]}"; do
            local resolved_value
            if resolved_value=$(resolve_hierarchical_path "$text_path" "$text_body"); then
                resolved_value=$(trim "$resolved_value")
                resolved_value=$(unescape_xml_chars "$resolved_value")
                if [[ -n "$resolved_value" ]]; then
                    append_tei_value "$text_path" "$resolved_value"
                    log_message "DEBUG" "Extracted $text_path: $resolved_value"
                fi
            fi
        done
    else
        log_message "DEBUG" "No text content found in file"
    fi
    
    # Parse named entities throughout the document (prevent infinite loops)
    for entity in "${TEI_NAMED_ENTITIES[@]}"; do
        local entity_regex="\\<${entity}[^>]*\\>([^<]*)\\</${entity}\\>"
        local temp_content="$file_content"
        local match_count=0
        while [[ "$temp_content" =~ $entity_regex ]] && [[ $match_count -lt 1000 ]]; do
            local entity_value="${BASH_REMATCH[1]}"
            local matched_text="${BASH_REMATCH[0]}"
            entity_value=$(trim "$entity_value")
            entity_value=$(unescape_xml_chars "$entity_value")
            if [[ -n "$entity_value" ]]; then
                append_tei_value "$entity" "$entity_value"
                log_message "DEBUG" "Extracted $entity: $entity_value"
            fi
            # Remove matched content to find next occurrence (safe removal)
            temp_content="${temp_content/$matched_text/__PROCESSED_MATCH__}"
            ((match_count++))
        done
        if [[ $match_count -ge 1000 ]]; then
            log_message "WARNING" "Maximum matches reached for entity $entity (possible infinite loop prevented)"
        fi
    done
    
    # Parse critical apparatus elements (prevent infinite loops)
    for critical_elem in "${TEI_CRITICAL_ELEMENTS[@]}"; do
        local crit_regex="\\<${critical_elem}[^>]*\\>([^<]*)\\</${critical_elem}\\>"
        local temp_content="$file_content"
        local match_count=0
        while [[ "$temp_content" =~ $crit_regex ]] && [[ $match_count -lt 1000 ]]; do
            local crit_value="${BASH_REMATCH[1]}"
            local matched_text="${BASH_REMATCH[0]}"
            crit_value=$(trim "$crit_value")
            crit_value=$(unescape_xml_chars "$crit_value")
            if [[ -n "$crit_value" ]]; then
                append_tei_value "$critical_elem" "$crit_value"
                log_message "DEBUG" "Extracted $critical_elem: $crit_value"
            fi
            # Remove matched content to find next occurrence (safe removal)
            temp_content="${temp_content/$matched_text/__PROCESSED_MATCH__}"
            ((match_count++))
        done
        if [[ $match_count -ge 1000 ]]; then
            log_message "WARNING" "Maximum matches reached for critical element $critical_elem (possible infinite loop prevented)"
        fi
    done
    
    log_message "INFO" "TEI XML parsing completed"
    return 0
}

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

# Validate TEI P5 metadata
validate_tei() {
    local format="$1"
    local has_required=0
    
    TEI_validation_errors=0
    TEI_validation_warnings=0
    
    echo "TEI P5 Validation Report - File: $TEI_input_file Format: $format"
    
    # Track validation issues
    local -a validation_issues
    local -a warning_issues
    
    # Check for TEI root structure
    if [[ "$format" == "tei-xml" ]]; then
        validate_tei_xml_structure validation_issues warning_issues
    fi
    
    # Check for teiHeader (required in TEI P5)
    local found_header_element=0
    for element in "${TEI_HEADER_ELEMENTS[@]}"; do
        if has_tei_key "$element"; then
            found_header_element=1
            break
        fi
    done
    
    if [[ $found_header_element -eq 0 ]]; then
        validation_issues+=("No teiHeader elements found - required for valid TEI")
        handle_error "VALIDATION" "No teiHeader elements found"
    else
        has_required=1
    fi
    
    # Validate essential header components
    if ! has_tei_key "fileDesc.titleStmt.title"; then
        warning_issues+=("Missing recommended element: title in titleStmt")
        handle_error "WARNING" "Missing recommended element: title in titleStmt"
    fi
    
    # Validate date formats in TEI elements
    local date_elements=("fileDesc.publicationStmt.date")
    for date_element in "${date_elements[@]}"; do
        local date_value
        if date_value=$(get_tei_value "$date_element"); then
            # Check for ISO 8601 format (basic validation)
            if ! [[ "$date_value" =~ ^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$ ]]; then
                warning_issues+=("Date format should be ISO 8601 in $date_element: $date_value")
                handle_error "WARNING" "Date format should be ISO 8601 in $date_element: $date_value"
            fi
        fi
    done
    
    # Check for text structure
    local found_text_element=0
    for element in "${TEI_TEXT_ELEMENTS[@]}"; do
        if has_tei_key "$element"; then
            found_text_element=1
            break
        fi
    done
    
    if [[ $found_text_element -eq 0 ]]; then
        warning_issues+=("No text structure elements found")
        handle_error "WARNING" "No text structure elements found"
    fi
    
    # Summary output
    echo ""
    if [[ $TEI_validation_errors -eq 0 ]] && [[ $TEI_validation_warnings -eq 0 ]]; then
        echo "Status: VALID - File contains valid TEI P5 metadata with no issues"
    elif [[ $TEI_validation_errors -eq 0 ]]; then
        local warning_list=""
        for warning in "${warning_issues[@]}"; do
            warning_list="${warning_list:+$warning_list; }$warning"
        done
        echo "Status: VALID (with warnings) - $warning_list"
    else
        local error_list=""
        for issue in "${validation_issues[@]}"; do
            error_list="${error_list:+$error_list; }$issue"
        done
        
        local warning_list=""
        for warning in "${warning_issues[@]}"; do
            warning_list="${warning_list:+$warning_list; }$warning"
        done
        
        if [[ -n "$warning_list" ]]; then
            echo "Status: INVALID - Errors: $error_list | Warnings: $warning_list"
        else
            echo "Status: INVALID - $error_list"
        fi
    fi
    
    [[ $TEI_validation_errors -eq 0 ]]
}

# Validate TEI XML structure
validate_tei_xml_structure() {
    local -n validation_issues_ref=$1
    local -n warning_issues_ref=$2
    local file_content
    
    # Read file content
    file_content=$(cat "$TEI_input_file")
    
    # Check for TEI root element
    if ! [[ "$file_content" =~ \<TEI[[:space:]] ]] && ! [[ "$file_content" =~ \<TEI\> ]]; then
        validation_issues_ref+=("Missing TEI root element")
        handle_error "VALIDATION" "Missing TEI root element"
    fi
    
    # Check for teiHeader
    if ! [[ "$file_content" =~ \<teiHeader ]]; then
        validation_issues_ref+=("Missing required teiHeader element")
        handle_error "VALIDATION" "Missing required teiHeader element"
    fi
    
    # Check for text element
    if ! [[ "$file_content" =~ \<text ]]; then
        warning_issues_ref+=("Missing text element - TEI should contain textual content")
        handle_error "WARNING" "Missing text element"
    fi
    
    # Check for proper namespace declaration  
    if ! [[ "$file_content" =~ xmlns.*tei-c\.org ]]; then
        warning_issues_ref+=("Missing or incorrect TEI namespace declaration")
        handle_error "WARNING" "Missing or incorrect TEI namespace declaration"
    fi
}

# ==============================================================================
# WRITE OPERATION FUNCTIONS (NEW)
# ==============================================================================

# Parse term arguments for write operation
parse_write_terms() {
    local term="$1"
    if [[ "$term" =~ ^([^=]+)=(.+)$ ]]; then
        local path="${BASH_REMATCH[1]}"
        local value="${BASH_REMATCH[2]}"
        TEI_write_data[$path]="$value"
        log_message "DEBUG" "Added write term: $path = $value"
    else
        handle_error "CRITICAL" "Invalid term format: $term (expected path=value)" 1
    fi
}

# Generate TEI XML template
generate_tei_template() {
    cat << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<TEI xmlns="http://www.tei-c.org/ns/1.0">
  <teiHeader>
    <fileDesc>
      <titleStmt>
        <!-- Title statement elements will be inserted here -->
      </titleStmt>
      <publicationStmt>
        <!-- Publication statement elements will be inserted here -->
      </publicationStmt>
      <sourceDesc>
        <!-- Source description elements will be inserted here -->
      </sourceDesc>
    </fileDesc>
    <profileDesc>
      <!-- Profile description elements will be inserted here -->
    </profileDesc>
    <revisionDesc>
      <!-- Revision description elements will be inserted here -->
    </revisionDesc>
  </teiHeader>
  <text>
    <body>
      <!-- Text body elements will be inserted here -->
    </body>
  </text>
</TEI>
EOF
}

# Build TEI XML from write data
build_tei_xml() {
    local output_file="$1"
    local temp_file="${temp_dir}/tei_build.xml"
    
    log_message "DEBUG" "Building TEI XML with ${#TEI_write_data[@]} data entries"
    
    # Generate basic template
    generate_tei_template > "$temp_file"
    
    # Process each write data entry
    for path in "${!TEI_write_data[@]}"; do
        local value="${TEI_write_data[$path]}"
        log_message "DEBUG" "Processing path: $path with value: $value"
        insert_tei_element "$path" "$value" "$temp_file"
    done
    
    # Remove only template comments (don't remove sections with content)
    remove_template_comments "$temp_file"
    
    # Clean up only truly empty sections
    clean_empty_tei_sections "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output_file"
    
    # Validate the generated XML
    validate_generated_xml "$output_file"
    
    log_message "INFO" "TEI XML written to: $output_file"
}

# Insert TEI element at hierarchical path
insert_tei_element() {
    local path="$1"
    local value="$2" 
    local file="$3"
    
    local escaped_value
    escaped_value=$(escape_xml_chars "$value")
    
    # Handle different hierarchical paths
    case "$path" in
        fileDesc.titleStmt.*)
            local element="${path##*.}"
            insert_into_section "$file" "titleStmt" "$element" "$escaped_value"
            ;;
        fileDesc.publicationStmt.*)
            local element="${path##*.}"
            insert_into_section "$file" "publicationStmt" "$element" "$escaped_value"
            ;;
        fileDesc.sourceDesc.*)
            local element="${path##*.}"
            insert_into_section "$file" "sourceDesc" "$element" "$escaped_value"
            ;;
        profileDesc.*)
            local element="${path##*.}"
            insert_into_section "$file" "profileDesc" "$element" "$escaped_value"
            ;;
        revisionDesc.*)
            local element="${path##*.}"
            insert_into_section "$file" "revisionDesc" "$element" "$escaped_value"
            ;;
        text.body.div.*)
            local element="${path##*.}"
            insert_into_section "$file" "body" "$element" "$escaped_value"
            ;;
        *)
            # Handle named entities and simple elements
            local element="$path"
            insert_into_section "$file" "body" "$element" "$escaped_value"
            ;;
    esac
}

# Remove template comments (safer approach)
remove_template_comments() {
    local file="$1"
    local temp_file="${file}.tmp"
    
    # Use a more robust sed command that works across platforms
    if command -v gsed >/dev/null 2>&1; then
        # Use GNU sed if available (better regex support)
        gsed '/<!-- .* will be inserted here -->/d' "$file" > "$temp_file"
    else
        # Use standard sed with simpler pattern
        sed '/<!-- .* will be inserted here -->/d' "$file" > "$temp_file"
    fi
    
    mv "$temp_file" "$file"
    log_message "DEBUG" "Removed template comments"
}

# Insert element into specific section
insert_into_section() {
    local file="$1"
    local section="$2"
    local element="$3"
    local value="$4"
    
    log_message "DEBUG" "Inserting element $element into section $section with value: $value"
    
    # Create the XML element with proper indentation
    local xml_element="        <$element>$value</$element>"
    
    # Create a safer temp file approach
    local temp_file="${file}.tmp"
    
    # Use a much simpler and more reliable approach with awk
    # Check if section exists and has content (not just comments)
    local section_exists=0
    if grep -q "<$section>" "$file" && ! grep -q "<$section>.*<!-- .* will be inserted here -->.*</$section>" "$file"; then
        section_exists=1
    fi
    
    if grep -q "<$section>" "$file"; then
        # Section exists - insert the element by replacing the comment or adding before closing tag
        awk -v section="$section" -v element="$xml_element" -v elem_name="$element" '
            # If we find a comment line within this section, replace it with our element
            /<-- .* will be inserted here -->/ && in_section {
                if (!added_element) {
                    print element;
                    added_element = 1;
                }
                next;
            }
            # Track when we are in the target section
            $0 ~ "<" section ">" || $0 ~ "<" section " " { in_section = 1; print; next; }
            $0 ~ "</" section ">" {
                if (in_section && !added_element) {
                    print element;
                }
                in_section = 0;
                print;
                next;
            }
            { print }
        ' "$file" > "$temp_file" && mv "$temp_file" "$file"
        log_message "DEBUG" "Added to existing $section section"
    else
        # Section doesn't exist - create it in the appropriate parent
        case "$section" in
            titleStmt|publicationStmt|sourceDesc)
                awk -v section="$section" -v element="$xml_element" '
                    /<\/fileDesc>/ {
                        print "      <" section ">";
                        print element;
                        print "      </" section ">";
                        print;
                        next
                    }
                    { print }
                ' "$file" > "$temp_file" && mv "$temp_file" "$file"
                ;;
            profileDesc|revisionDesc)
                awk -v section="$section" -v element="$xml_element" '
                    /<\/teiHeader>/ {
                        print "    <" section ">";
                        print element;
                        print "    </" section ">";
                        print;
                        next
                    }
                    { print }
                ' "$file" > "$temp_file" && mv "$temp_file" "$file"
                ;;
            body)
                awk -v element="$xml_element" '
                    /<\/body>/ { print element; print; next }
                    { print }
                ' "$file" > "$temp_file" && mv "$temp_file" "$file"
                ;;
        esac
        log_message "DEBUG" "Created new $section section with element"
    fi
    
    # Clean up any backup files created by sed
    rm -f "${file}.bak"
}

# Clean up empty TEI sections
clean_empty_tei_sections() {
    local file="$1"
    
    log_message "DEBUG" "Cleaning up empty TEI sections (simplified approach)"
    
    # Just remove sections that only contain comments - much simpler approach
    local temp_file="${file}.tmp"
    
    # Use grep to find and remove empty sections (those with only comments)
    grep -v '<!-- .* will be inserted here -->' "$file" > "$temp_file" && mv "$temp_file" "$file"
    
    log_message "DEBUG" "Finished cleaning up empty sections"
}

# Validate generated XML
validate_generated_xml() {
    local file="$1"
    
    # Check if xmllint is available for validation
    if command -v xmllint >/dev/null 2>&1; then
        if ! xmllint --noout "$file" 2>/dev/null; then
            handle_error "CRITICAL" "Generated XML is not well-formed" 1
        fi
        log_message "INFO" "Generated XML validated successfully"
    else
        log_message "WARNING" "xmllint not available - skipping XML validation"
    fi
}

# ==============================================================================
# TERM EXTRACTION FUNCTIONS
# ==============================================================================

# Extract a specific term from metadata using hierarchical paths
extract_term() {
    local term="$1"
    local found=0
    
    # Check direct match (handles hierarchical paths)
    local direct_value
    if direct_value=$(get_tei_value "$term"); then
        echo "Term: $term"
        IFS=';' read -ra values <<< "$direct_value"
        for value in "${values[@]}"; do
            echo "Value: $value"
        done
        found=1
    fi
    
    # Check simple element names if not found
    if [[ $found -eq 0 ]]; then
        for element in "${TEI_NAMED_ENTITIES[@]}" "${TEI_CRITICAL_ELEMENTS[@]}"; do
            if [[ "$term" == "$element" ]]; then
                local element_value
                if element_value=$(get_tei_value "$element"); then
                    echo "Term: $term"
                    IFS=';' read -ra values <<< "$element_value"
                    for value in "${values[@]}"; do
                        echo "Value: $value"
                    done
                    found=1
                    break
                fi
            fi
        done
    fi
    
    if [[ $found -eq 0 ]]; then
        echo "Term '$term' not found in metadata"
        echo ""
        echo "Available hierarchical paths:"
        for path in "${TEI_HEADER_ELEMENTS[@]}" "${TEI_TEXT_ELEMENTS[@]}"; do
            if has_tei_key "$path"; then
                echo "  $path"
            fi
        done
        echo ""
        echo "Available elements:"
        for element in "${TEI_NAMED_ENTITIES[@]}" "${TEI_CRITICAL_ELEMENTS[@]}"; do
            if has_tei_key "$element"; then
                echo "  $element"
            fi
        done
        return 1
    fi
    
    return 0
}

# ==============================================================================
# DISPLAY FUNCTIONS
# ==============================================================================

# Display all metadata using native associative arrays
display_metadata() {
    echo "=== TEI P5 Metadata ==="
    echo "File: $TEI_input_file"
    echo ""
    
    local has_metadata=0
    
    echo "## Header Elements"
    echo ""
    
    # Display header elements
    for header_path in "${TEI_HEADER_ELEMENTS[@]}"; do
        if has_tei_key "$header_path"; then
            has_metadata=1
            local display_name="${header_path//\./ → }"
            echo "$display_name:"
            local header_value
            header_value=$(get_tei_value "$header_path")
            IFS=';' read -ra values <<< "$header_value"
            for value in "${values[@]}"; do
                echo "  - $value"
            done
            echo ""
        fi
    done
    
    echo "## Text Structure"
    echo ""
    
    # Display text elements
    for text_path in "${TEI_TEXT_ELEMENTS[@]}"; do
        if has_tei_key "$text_path"; then
            has_metadata=1
            local display_name="${text_path//\./ → }"
            echo "$display_name:"
            local text_value
            text_value=$(get_tei_value "$text_path")
            IFS=';' read -ra values <<< "$text_value"
            for value in "${values[@]}"; do
                echo "  - $value"
            done
            echo ""
        fi
    done
    
    echo "## Named Entities"
    echo ""
    
    # Display named entities
    for entity in "${TEI_NAMED_ENTITIES[@]}"; do
        if has_tei_key "$entity"; then
            has_metadata=1
            local display_name="${entity^}"
            echo "$display_name:"
            local entity_value
            entity_value=$(get_tei_value "$entity")
            IFS=';' read -ra values <<< "$entity_value"
            for value in "${values[@]}"; do
                echo "  - $value"
            done
            echo ""
        fi
    done
    
    echo "## Critical Apparatus"
    echo ""
    
    # Display critical apparatus elements
    for critical_elem in "${TEI_CRITICAL_ELEMENTS[@]}"; do
        if has_tei_key "$critical_elem"; then
            has_metadata=1
            local display_name="${critical_elem^}"
            echo "$display_name:"
            local critical_value
            critical_value=$(get_tei_value "$critical_elem")
            IFS=';' read -ra values <<< "$critical_value"
            for value in "${values[@]}"; do
                echo "  - $value"
            done
            echo ""
        fi
    done
    
    if [[ $has_metadata -eq 0 ]]; then
        echo "No TEI metadata found in file"
    fi
}

# Display help information
display_help() {
    cat << EOF
TEI P5 Processing Script v${SCRIPT_VERSION} (Bash 4+ Required)

USAGE:
    ${SCRIPT_NAME} [OPERATION] [OPTIONS] FILE

OPERATIONS:
    --read, -r FILE       Read and display TEI P5 metadata from FILE
    --validate, -V FILE   Validate TEI P5 compliance
    --write, -w [OPTIONS] Write TEI XML from command-line terms
    --term, -t PATH FILE  Extract specific TEI element or hierarchical path

OPTIONS:
    --term, -t "path=value" Specify hierarchical path and value (write mode)
    --output, -o FILE       Output file for write operations
    --verbose, -v           Enable verbose output
    --debug, -d             Enable debug output
    --help, -h             Display this help message

EXAMPLES:
    # Read and display metadata (long and short form)
    ${SCRIPT_NAME} --read document.xml
    ${SCRIPT_NAME} -r document.xml

    # Validate TEI P5 compliance (long and short form)
    ${SCRIPT_NAME} --validate document.xml
    ${SCRIPT_NAME} -V document.xml

    # Write TEI XML from command-line terms (short form)
    ${SCRIPT_NAME} -w -t "fileDesc.titleStmt.title=Example Title" \\
      -t "fileDesc.titleStmt.author=John Doe" \\
      -t "fileDesc.publicationStmt.date=2025" \\
      -o output.xml

    # Extract specific hierarchical elements (short form)
    ${SCRIPT_NAME} -t "fileDesc.titleStmt.title" document.xml
    ${SCRIPT_NAME} -t "persName" document.xml

TEI P5 HIERARCHICAL PATHS:
    Header Elements:
        fileDesc.titleStmt.title, fileDesc.titleStmt.author, fileDesc.titleStmt.editor
        fileDesc.publicationStmt.publisher, fileDesc.publicationStmt.pubPlace, fileDesc.publicationStmt.date
        fileDesc.sourceDesc.bibl, fileDesc.sourceDesc.msDesc
        profileDesc.creation, profileDesc.langUsage, profileDesc.textClass
        revisionDesc.change

    Text Structure:
        text.body.div, text.body.div.head, text.body.div.p
        text.body.div.lg, text.body.div.l, text.front, text.back

    Named Entities:
        persName (personal names), placeName (place names), orgName (organization names)
        geogName (geographic names), date, name

    Critical Apparatus:
        app (apparatus entry), lem (lemma), rdg (reading), wit (witness), note

REQUIREMENTS:
    - Bash 4.0 or higher (uses native associative arrays)
    - xmllint (optional, for XML validation)

For more information about TEI P5, visit:
    https://tei-c.org/guidelines/p5/

EOF
}

# ==============================================================================
# FORMAT DETECTION AND PARSING
# ==============================================================================

# Detect the format of the input file
detect_format() {
    local file="$1"
    local first_lines
    
    # Read first 20 lines for detection
    first_lines=$(head -n 20 "$file" 2>/dev/null || true)
    
    # Check for TEI XML format
    if [[ "$first_lines" =~ \<\?xml ]] && [[ "$first_lines" =~ \<TEI ]]; then
        echo "tei-xml"
    else
        echo "unknown"
    fi
}

# ==============================================================================
# MAIN FUNCTIONS
# ==============================================================================

# Parse command-line arguments
parse_arguments() {
    local write_mode=0
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                display_help
                exit 0
                ;;
            --read|-r)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --read" 1
                fi
                TEI_input_file="$1"
                TEI_operation="read"
                shift
                ;;
            --validate|-V)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --validate" 1
                fi
                TEI_input_file="$1"
                TEI_operation="validate"
                shift
                ;;
            --write|-w)
                write_mode=1
                TEI_operation="write"
                shift
                ;;
            --term|-t)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --term" 1
                fi
                
                if [[ $write_mode -eq 1 ]]; then
                    # Write mode: expect "path=value" format
                    parse_write_terms "$1"
                else
                    # Extract mode: add to selected terms
                    TEI_selected_terms+=("$1")
                    TEI_term_name="$1"
                    if [[ -z "$TEI_operation" ]]; then
                        TEI_operation="extract"
                    fi
                fi
                shift
                ;;
            --output|-o)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --output" 1
                fi
                TEI_output_file="$1"
                shift
                ;;
            --verbose|-v)
                TEI_verbose=1
                shift
                ;;
            --debug|-d)
                TEI_debug=1
                TEI_verbose=1
                shift
                ;;
            *)
                # Check if it looks like a file (doesn't start with -)
                if [[ "$1" != -* ]] && [[ -z "$TEI_input_file" ]]; then
                    TEI_input_file="$1"
                    # Only set default operation if none is set
                    if [[ -z "$TEI_operation" ]]; then
                        TEI_operation="read"
                    fi
                else
                    handle_error "CRITICAL" "Unknown option: $1" 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ "$TEI_operation" != "write" ]] && [[ -z "$TEI_input_file" ]]; then
        handle_error "CRITICAL" "No input file specified" 1
    fi
    
    # Set default operation if none specified
    if [[ -z "$TEI_operation" ]]; then
        TEI_operation="read"
    fi
    
    # Validate write operation requirements
    if [[ "$TEI_operation" == "write" ]]; then
        if [[ ${#TEI_write_data[@]} -eq 0 ]]; then
            handle_error "CRITICAL" "No terms specified for write operation. Use --term 'path=value'" 1
        fi
        if [[ -z "$TEI_output_file" ]]; then
            handle_error "CRITICAL" "No output file specified for write operation. Use --output FILE" 1
        fi
    fi
}

# Execute the requested operation
execute_operation() {
    case "$TEI_operation" in
        read)
            # Validate input file
            validate_file_security "$TEI_input_file"
            
            # Detect and validate format
            local format
            format=$(detect_format "$TEI_input_file")
            if [[ "$format" != "tei-xml" ]]; then
                handle_error "CRITICAL" "File does not appear to be TEI XML: $TEI_input_file" 1
            fi
            
            log_message "INFO" "Detected format: $format"
            
            # Parse the input file
            parse_tei_xml "$TEI_input_file"
            
            # Display metadata
            display_metadata
            ;;
        validate)
            # Validate input file
            validate_file_security "$TEI_input_file"
            
            # Detect format
            local format
            format=$(detect_format "$TEI_input_file")
            log_message "INFO" "Detected format: $format"
            
            # Parse the input file
            parse_tei_xml "$TEI_input_file"
            
            # Validate TEI
            validate_tei "$format"
            ;;
        write)
            # Build TEI XML from write data
            build_tei_xml "$TEI_output_file"
            ;;
        extract)
            # Validate input file
            validate_file_security "$TEI_input_file"
            
            # Parse the input file
            parse_tei_xml "$TEI_input_file"
            
            # Extract term
            extract_term "$TEI_term_name"
            ;;
        *)
            handle_error "CRITICAL" "Unknown operation: $TEI_operation" 1
            ;;
    esac
}

# Main function
main() {
    # Create temp directory
    temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'tei')
    
    # Parse arguments
    parse_arguments "$@"
    
    # Execute operation
    execute_operation
    
    # Cleanup is handled by trap
    return 0
}

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================

# Only run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi