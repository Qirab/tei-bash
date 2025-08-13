#!/usr/bin/env bash
#
# dublincore.sh - Dublin Core Metadata Processing Script
# 
# A comprehensive bash script for processing Dublin Core metadata in XML, text, and HTML formats.
# Compatible with bash 3.2 or higher.
#
# Version: v1.0.0
# Author: Qirab™ project of the Thesaurus Islamicus Foundation 
# License: CC0
#
# Usage:
#   dublincore.sh --read <file>
#   dublincore.sh --validate --read <file>
#   dublincore.sh --read <file> --format <format> --output <file>
#   dublincore.sh --term <term> --read <file>
#   dublincore.sh --term <term> --term <term> --format <format> --output <file>
#   dublincore.sh --help
#

set -o errexit   # Exit on error
set -o pipefail  # Exit on pipe failure
# Note: nounset disabled due to bash associative array behavior

# ==============================================================================
# CONSTANTS AND GLOBAL VARIABLES
# ==============================================================================

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Dublin Core namespaces
readonly DC_NS="http://purl.org/dc/elements/1.1/"
readonly DCTERMS_NS="http://purl.org/dc/terms/"

# Dublin Core 1.1 elements
readonly -a DC_ELEMENTS=(
    "title" "creator" "subject" "description" "publisher"
    "contributor" "date" "type" "format" "identifier"
    "source" "language" "relation" "coverage" "rights"
)

# DCMI Metadata Terms (extended set)
readonly -a DCTERMS_ELEMENTS=(
    "abstract" "accessRights" "accrualMethod" "accrualPeriodicity" "accrualPolicy"
    "alternative" "audience" "available" "bibliographicCitation" "conformsTo"
    "created" "dateAccepted" "dateCopyrighted" "dateSubmitted" "educationLevel"
    "extent" "hasFormat" "hasPart" "hasVersion" "instructionalMethod"
    "isFormatOf" "isPartOf" "isReferencedBy" "isReplacedBy" "isRequiredBy"
    "issued" "isVersionOf" "license" "mediator" "medium"
    "modified" "provenance" "references" "replaces" "requires"
    "rightsHolder" "spatial" "tableOfContents" "temporal" "valid"
)

# File size limits (100MB default)
readonly MAX_FILE_SIZE=$((100 * 1024 * 1024))

# Global variables with namespace prefix to avoid pollution
# Using indexed arrays for bash 3.2 compatibility (format: "key=value")
declare -a DC_metadata
declare -a DC_filtered_metadata
declare -a DC_selected_terms
declare -i DC_validation_errors=0
declare -i DC_validation_warnings=0
declare DC_operation=""
declare DC_input_file=""
declare DC_output_file=""
declare DC_target_format=""
declare DC_term_name=""
declare DC_subset_mode=0
declare DC_create_mode=0
declare DC_clean_mode=0
declare DC_select_index=0
declare DC_verbose=0
declare DC_debug=0

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

# Bash 3.2 compatible associative array functions using indexed arrays
# Format: "key=value" stored in indexed array

# Get value from metadata array by key
get_metadata_value() {
    local key="$1"
    local i
    for i in "${!DC_metadata[@]}"; do
        if [[ "${DC_metadata[i]}" == "$key="* ]]; then
            echo "${DC_metadata[i]#*=}"
            return 0
        fi
    done
    return 1
}

# Set value in metadata array (replaces if exists, adds if new)
set_metadata_value() {
    local key="$1"
    local value="$2"
    local i found=0
    
    # Check if key already exists and update it
    for i in "${!DC_metadata[@]}"; do
        if [[ "${DC_metadata[i]}" == "$key="* ]]; then
            DC_metadata[i]="$key=$value"
            found=1
            break
        fi
    done
    
    # If key doesn't exist, add it
    if [[ $found -eq 0 ]]; then
        DC_metadata+=("$key=$value")
    fi
}

# Append value to existing metadata (for multiple values)
append_metadata_value() {
    local key="$1"
    local value="$2"
    local existing_value
    
    if existing_value=$(get_metadata_value "$key"); then
        set_metadata_value "$key" "$existing_value;$value"
    else
        set_metadata_value "$key" "$value"
    fi
}

# Get value from filtered metadata array by key
get_filtered_value() {
    local key="$1"
    local i
    for i in "${!DC_filtered_metadata[@]}"; do
        if [[ "${DC_filtered_metadata[i]}" == "$key="* ]]; then
            echo "${DC_filtered_metadata[i]#*=}"
            return 0
        fi
    done
    return 1
}

# Set value in filtered metadata array
set_filtered_value() {
    local key="$1"
    local value="$2"
    local i found=0
    
    # Check if key already exists and update it
    for i in "${!DC_filtered_metadata[@]}"; do
        if [[ "${DC_filtered_metadata[i]}" == "$key="* ]]; then
            DC_filtered_metadata[i]="$key=$value"
            found=1
            break
        fi
    done
    
    # If key doesn't exist, add it
    if [[ $found -eq 0 ]]; then
        DC_filtered_metadata+=("$key=$value")
    fi
}

# Clear metadata arrays
clear_metadata() {
    DC_metadata=()
}

clear_filtered_metadata() {
    DC_filtered_metadata=()
}

# Get all metadata keys
get_metadata_keys() {
    local i
    for i in "${!DC_metadata[@]}"; do
        echo "${DC_metadata[i]%%=*}"
    done
}

# Get all filtered metadata keys
get_filtered_keys() {
    local i
    for i in "${!DC_filtered_metadata[@]}"; do
        echo "${DC_filtered_metadata[i]%%=*}"
    done
}

# ==============================================================================

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
            if [[ $DC_verbose -eq 1 ]]; then
                echo "[$timestamp] INFO: $message"
            fi
            ;;
        DEBUG)
            if [[ $DC_debug -eq 1 ]]; then
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
            ((DC_validation_errors++))
            ;;
        FORMAT)
            log_message "ERROR" "$error_message"
            return 1
            ;;
        WARNING)
            log_message "WARNING" "$error_message"
            ((DC_validation_warnings++))
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
    
    # Use printf and sed for more reliable escaping
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
    
    # Use sed for reliable unescaping (order matters - &amp; must be last)
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

# ==============================================================================
# FORMAT DETECTION FUNCTIONS
# ==============================================================================

# Detect the format of the input file
detect_format() {
    local file="$1"
    local first_lines
    
    # Read first 50 lines for detection
    first_lines=$(head -n 50 "$file" 2>/dev/null || true)
    
    # Check for XML format
    if [[ "$first_lines" =~ \<\?xml ]] || [[ "$first_lines" =~ \<metadata ]] || [[ "$first_lines" =~ \<dc: ]]; then
        echo "xml"
        return 0
    fi
    
    # Check for HTML format
    if [[ "$first_lines" =~ \<html ]] || [[ "$first_lines" =~ \<HTML ]] || [[ "$first_lines" =~ \<meta[[:space:]] ]]; then
        echo "html"
        return 0
    fi
    
    # Check for text format (key: value pairs)
    if [[ "$first_lines" =~ ^[A-Za-z]+:[[:space:]] ]]; then
        echo "text"
        return 0
    fi
    
    # Default to text if unable to determine
    echo "text"
}

# ==============================================================================
# PARSING FUNCTIONS
# ==============================================================================

# Parse XML format Dublin Core
parse_xml() {
    local file="$1"
    local line tag value namespace element
    
    # Clear existing metadata
    clear_metadata
    
    while IFS= read -r line; do
        # Skip comments and empty lines
        if [[ "$line" == *"<!--"* ]]; then
            continue
        fi
        if [[ -z "$(trim "$line")" ]]; then
            continue
        fi
        
        # Extract DC elements with namespace - improved regex pattern
        if [[ "$line" =~ \<dc:([^[:space:]\>]+)\>([^\<]*)\</dc:([^\>]+)\> ]]; then
            element="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            
            if [[ -n "$element" ]] && [[ -n "$value" ]]; then
                element=$(trim "$element")
                value=$(trim "$value")
                value=$(unescape_xml_chars "$value")
                
                # Store in metadata array
                append_metadata_value "$element" "$value"
            fi
        fi
        
        # Extract DCTERMS elements - improved regex pattern
        if [[ "$line" =~ \<dcterms:([^[:space:]\>]+)\>([^\<]*)\</dcterms:([^\>]+)\> ]]; then
            element="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            
            if [[ -n "$element" ]] && [[ -n "$value" ]]; then
                element=$(trim "$element")
                value=$(trim "$value")
                value=$(unescape_xml_chars "$value")
                
                # Store with dcterms prefix
                append_metadata_value "dcterms:$element" "$value"
            fi
        fi
        
        # Handle elements without namespace prefix
        for dc_elem in "${DC_ELEMENTS[@]}"; do
            if [[ "$line" =~ \<${dc_elem}\>([^\<]*)\</${dc_elem}\> ]]; then
                value="${BASH_REMATCH[1]}"
                
                if [[ -n "$value" ]]; then
                    element=$(trim "$dc_elem")
                    value=$(trim "$value")
                    value=$(unescape_xml_chars "$value")
                    
                    append_metadata_value "$element" "$value"
                fi
                break
            fi
        done
    done < "$file"
    
    return 0
}

# Parse text format Dublin Core
parse_text() {
    local file="$1"
    local line key value
    
    # Clear existing metadata
    clear_metadata
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$(trim "$line")" ]]; then
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Parse key: value format
        if [[ "$line" == *":"* ]]; then
            key="${line%%:*}"
            value="${line#*:}"
            
            key=$(trim "$key")
            value=$(trim "$value")
            
            # Normalize key to lowercase
            key="${key,,}"
            
            # Check if it's a valid DC element
            local valid_key=0
            for dc_elem in "${DC_ELEMENTS[@]}"; do
                if [[ "$key" == "$dc_elem" ]]; then
                    valid_key=1
                    break
                fi
            done
            
            # Also check DCTERMS elements
            if [[ $valid_key -eq 0 ]]; then
                for dcterm_elem in "${DCTERMS_ELEMENTS[@]}"; do
                    if [[ "$key" == "$dcterm_elem" ]]; then
                        key="dcterms:$key"
                        valid_key=1
                        break
                    fi
                done
            fi
            
            if [[ $valid_key -eq 1 ]] && [[ -n "$value" ]]; then
                append_metadata_value "$key" "$value"
            fi
        fi
    done < "$file"
    
    return 0
}

# Parse HTML format Dublin Core (meta tags)
parse_html() {
    local file="$1"
    local line element value prefix
    
    # Clear existing metadata
    clear_metadata
    
    # Process line by line to find meta tags
    while IFS= read -r line; do
        # Skip lines without meta tags
        if [[ "$line" != *"<meta"* ]]; then
            continue
        fi
        
        # Check for DC meta tags with name and content attributes
        if [[ "$line" == *"name="* ]] && [[ "$line" == *"content="* ]]; then
            # Extract name attribute
            local name_part="${line#*name=}"
            # Handle both quote types
            if [[ "$name_part" == \"* ]]; then
                name_part="${name_part#\"}"
                name_part="${name_part%%\"*}"
            elif [[ "$name_part" == \'* ]]; then
                name_part="${name_part#\'}"
                name_part="${name_part%%\'*}"
            fi
            
            # Extract content attribute
            local content_part="${line#*content=}"
            # Handle both quote types
            if [[ "$content_part" == \"* ]]; then
                content_part="${content_part#\"}"
                content_part="${content_part%%\"*}"
            elif [[ "$content_part" == \'* ]]; then
                content_part="${content_part#\'}"
                content_part="${content_part%%\'*}"
            fi
            
            # Check if it's a Dublin Core element
            if [[ "$name_part" == DC.* ]] || [[ "$name_part" == dc.* ]]; then
                element="${name_part#*.}"
                value="$content_part"
                
                element=$(trim "$element")
                value=$(trim "$value")
                value=$(unescape_xml_chars "$value")
                
                if [[ -n "$value" ]]; then
                    append_metadata_value "$element" "$value"
                fi
            elif [[ "$name_part" == dcterms.* ]]; then
                element="${name_part#*.}"
                value="$content_part"
                
                element=$(trim "$element")
                value=$(trim "$value")
                value=$(unescape_xml_chars "$value")
                
                if [[ -n "$value" ]]; then
                    append_metadata_value "dcterms:$element" "$value"
                fi
            fi
        fi
    done < "$file"
    
    return 0
}

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

# Validate Dublin Core metadata
validate_dublin_core() {
    local format="$1"
    local has_required=0
    local has_errors=0
    
    DC_validation_errors=0
    DC_validation_warnings=0
    
    echo "Dublin Core Validation Report - File: $DC_input_file Format: $format"
    
    # Track validation issues
    local validation_issues=()
    local warning_issues=()
    
    # Check for at least one required element
    for element in "${DC_ELEMENTS[@]}"; do
        if get_metadata_value "$element" >/dev/null 2>&1; then
            has_required=1
            break
        fi
    done
    
    if [[ $has_required -eq 0 ]]; then
        validation_issues+=("No Dublin Core elements found in file")
        handle_error "VALIDATION" "No Dublin Core elements found"
        has_errors=1
    fi
    
    # Validate title (strongly recommended)
    if ! get_metadata_value "title" >/dev/null 2>&1; then
        warning_issues+=("Missing recommended element: title")
        handle_error "WARNING" "Missing recommended element: title"
    fi
    
    # Validate date format if present
    local date_value
    if date_value=$(get_metadata_value "date"); then
        # Check for ISO 8601 format (basic validation)
        if ! [[ "$date_value" =~ ^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$ ]]; then
            warning_issues+=("Date format should be ISO 8601: $date_value")
            handle_error "WARNING" "Date format should be ISO 8601: $date_value"
        fi
    fi
    
    # Validate language codes if present
    local lang_value
    if lang_value=$(get_metadata_value "language"); then
        # Check for ISO 639 format (basic validation)
        if ! [[ "$lang_value" =~ ^[a-z]{2,3}(-[A-Z]{2})?$ ]]; then
            warning_issues+=("Language code should follow ISO 639: $lang_value")
            handle_error "WARNING" "Language code should follow ISO 639: $lang_value"
        fi
    fi
    
    # Validate format-specific structure
    case "$format" in
        xml)
            validate_xml_structure validation_issues warning_issues
            ;;
        html)
            validate_html_structure validation_issues warning_issues
            ;;
        text)
            validate_text_structure validation_issues warning_issues
            ;;
    esac
    
    # Summary - single line output
    echo ""
    if [[ $DC_validation_errors -eq 0 ]] && [[ $DC_validation_warnings -eq 0 ]]; then
        echo "Status: VALID - File contains valid Dublin Core metadata with no issues"
    elif [[ $DC_validation_errors -eq 0 ]]; then
        # Join warnings with semicolon separator
        local warning_list=""
        for warning in "${warning_issues[@]}"; do
            if [[ -n "$warning_list" ]]; then
                warning_list="$warning_list; $warning"
            else
                warning_list="$warning"
            fi
        done
        echo "Status: VALID (with warnings) - $warning_list"
    else
        # Build error and warning lists
        local error_list=""
        for issue in "${validation_issues[@]}"; do
            if [[ -n "$error_list" ]]; then
                error_list="$error_list; $issue"
            else
                error_list="$issue"
            fi
        done
        
        local warning_list=""
        for warning in "${warning_issues[@]}"; do
            if [[ -n "$warning_list" ]]; then
                warning_list="$warning_list; $warning"
            else
                warning_list="$warning"
            fi
        done
        
        if [[ -n "$warning_list" ]]; then
            echo "Status: INVALID - Errors: $error_list | Warnings: $warning_list"
        else
            echo "Status: INVALID - $error_list"
        fi
    fi
    
    if [[ $DC_validation_errors -eq 0 ]]; then
        return 0
    else
        return 1
    fi
}

# Validate XML structure
validate_xml_structure() {
    local -n validation_issues_ref=$1
    local -n warning_issues_ref=$2
    local file="$DC_input_file"
    local has_xml_declaration=0
    local has_proper_encoding=0
    
    # Check for XML declaration
    if head -n 1 "$file" | grep -q '<?xml'; then
        has_xml_declaration=1
        
        # Check for UTF-8 encoding
        if head -n 1 "$file" | grep -qi 'encoding.*utf-8'; then
            has_proper_encoding=1
        else
            warning_issues_ref+=("XML should use UTF-8 encoding")
            handle_error "WARNING" "XML should use UTF-8 encoding"
        fi
    else
        warning_issues_ref+=("Missing XML declaration")
        handle_error "WARNING" "Missing XML declaration"
    fi
    
    # Check for balanced tags (improved)
    local content=$(cat "$file")
    
    # Remove line breaks to handle multi-line tags, then remove XML declarations and comments
    content=$(echo "$content" | tr -d '\n' | sed 's/<\?[^>]*\?>//g' | sed 's/<!--[^>]*-->//g')
    
    # Count opening tags (including multi-line tags with attributes and namespaces)
    # Match any opening tag (including those with colons for namespaces) that doesn't end with />
    local open_tags=$(echo "$content" | grep -oE '<[a-zA-Z:][^>]*>' | grep -v '/>' | wc -l)
    
    # Count closing tags
    local close_tags=$(echo "$content" | grep -oE '</[^>]+>' | wc -l)
    
    if [[ $open_tags -ne $close_tags ]]; then
        validation_issues_ref+=("Unbalanced XML tags (open: $open_tags, close: $close_tags)")
        handle_error "VALIDATION" "Unbalanced XML tags (open: $open_tags, close: $close_tags)"
    fi
}

# Validate HTML structure
validate_html_structure() {
    local -n validation_issues_ref=$1
    local -n warning_issues_ref=$2
    local file="$DC_input_file"
    local has_head_section=0
    
    # Check for head section
    if grep -qi '<head' "$file"; then
        has_head_section=1
    else
        handle_error "WARNING" "HTML should have a <head> section for metadata"
    fi
    
    # Check for proper meta tag format
    if ! grep -qi '<meta.*name=.*DC\.' "$file" && ! grep -qi '<meta.*name=.*dc\.' "$file"; then
        handle_error "WARNING" "No Dublin Core meta tags found with DC. prefix"
    fi
}

# Validate text structure
validate_text_structure() {
    local -n validation_issues_ref=$1
    local -n warning_issues_ref=$2
    local file="$DC_input_file"
    local has_valid_format=1
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$(trim "$line")" ]]; then
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Check for key: value format
        if ! [[ "$line" =~ ^[^:]+:.*$ ]]; then
            handle_error "WARNING" "Invalid line format (expected 'key: value'): $line"
            has_valid_format=0
        fi
    done < "$file"
    
    return 0
}

# ==============================================================================
# CONVERSION FUNCTIONS
# ==============================================================================

# Convert metadata to XML format
convert_to_xml() {
    local output="$1"
    local temp_file="${temp_dir}/output.xml"
    
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"'
        echo '          xmlns:dcterms="http://purl.org/dc/terms/">'
        
        # Output DC elements
        for element in "${DC_ELEMENTS[@]}"; do
            local element_value
            if element_value=$(get_metadata_value "$element"); then
                IFS=';' read -ra values <<< "$element_value"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <dc:$element>$value</dc:$element>"
                done
            fi
        done
        
        # Output DCTERMS elements
        local all_keys
        all_keys=$(get_metadata_keys)
        while IFS= read -r key; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                local key_value
                if key_value=$(get_metadata_value "$key"); then
                    IFS=';' read -ra values <<< "$key_value"
                    for value in "${values[@]}"; do
                        value=$(escape_xml_chars "$value")
                        echo "    <dcterms:$element>$value</dcterms:$element>"
                    done
                fi
            fi
        done <<< "$all_keys"
        
        echo '</metadata>'
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "XML output written to: $output"
    return 0
}

# Convert metadata to text format
convert_to_text() {
    local output="$1"
    local temp_file="${temp_dir}/output.txt"
    
    {
        echo "# Dublin Core Metadata"
        echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        
        # Output DC elements
        for element in "${DC_ELEMENTS[@]}"; do
            local element_value
            if element_value=$(get_metadata_value "$element"); then
                IFS=';' read -ra values <<< "$element_value"
                for value in "${values[@]}"; do
                    # Capitalize first letter of element name
                    local display_name="${element^}"
                    echo "$display_name: $value"
                done
            fi
        done
        
        # Output DCTERMS elements
        local all_keys
        all_keys=$(get_metadata_keys)
        while IFS= read -r key; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                local display_name="${element^}"
                local key_value
                if key_value=$(get_metadata_value "$key"); then
                    IFS=';' read -ra values <<< "$key_value"
                    for value in "${values[@]}"; do
                        echo "$display_name: $value"
                    done
                fi
            fi
        done <<< "$all_keys"
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "Text output written to: $output"
    return 0
}

# Convert metadata to HTML format
convert_to_html() {
    local output="$1"
    local temp_file="${temp_dir}/output.html"
    
    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en">'
        echo '<head>'
        echo '    <meta charset="UTF-8">'
        echo '    <title>Dublin Core Metadata</title>'
        
        # Output DC elements as meta tags
        for element in "${DC_ELEMENTS[@]}"; do
            local element_value
            if element_value=$(get_metadata_value "$element"); then
                IFS=';' read -ra values <<< "$element_value"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <meta name=\"DC.$element\" content=\"$value\">"
                done
            fi
        done
        
        # Output DCTERMS elements as meta tags
        for key in "${!DC_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                IFS=';' read -ra values <<< "${DC_metadata[$key]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <meta name=\"dcterms.$element\" content=\"$value\">"
                done
            fi
        done
        
        echo '</head>'
        echo '<body>'
        echo '    <h1>Dublin Core Metadata</h1>'
        echo '    <dl>'
        
        # Output human-readable content
        for element in "${DC_ELEMENTS[@]}"; do
            if [[ -n "${DC_metadata[$element]:-}" ]]; then
                local display_name="${element^}"
                echo "        <dt><strong>$display_name:</strong></dt>"
                IFS=';' read -ra values <<< "${DC_metadata[$element]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "        <dd>$value</dd>"
                done
            fi
        done
        
        # Output DCTERMS elements
        for key in "${!DC_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                local display_name="${element^}"
                echo "        <dt><strong>$display_name (DCTERMS):</strong></dt>"
                IFS=';' read -ra values <<< "${DC_metadata[$key]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "        <dd>$value</dd>"
                done
            fi
        done
        
        echo '    </dl>'
        echo '    <footer>'
        echo "        <p><em>Generated: $(date '+%Y-%m-%d %H:%M:%S')</em></p>"
        echo '    </footer>'
        echo '</body>'
        echo '</html>'
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "HTML output written to: $output"
    return 0
}

# ==============================================================================
# TERM EXTRACTION FUNCTIONS
# ==============================================================================

# Extract a specific term from metadata
extract_term() {
    local term="$1"
    local normalized_term="${term,,}"  # Convert to lowercase
    local found=0
    
    # Check direct match
    local direct_value
    if direct_value=$(get_metadata_value "$normalized_term"); then
        IFS=';' read -ra values <<< "$direct_value"
        
        # Handle select mode
        if [[ $DC_select_index -gt 0 ]]; then
            if [[ $DC_select_index -le ${#values[@]} ]]; then
                local selected_value="${values[$((DC_select_index-1))]}"
                if [[ $DC_clean_mode -eq 1 ]]; then
                    echo "$selected_value"
                else
                    echo "Term: $term"
                    echo "Value: $selected_value"
                fi
            else
                if [[ $DC_clean_mode -eq 0 ]]; then
                    echo "Term '$term' has only ${#values[@]} value(s), cannot select position $DC_select_index"
                fi
                return 1
            fi
        else
            # Normal mode (all values)
            if [[ $DC_clean_mode -eq 1 ]]; then
                # Output values separated by semicolons
                echo "$direct_value"
            else
                echo "Term: $term"
                for value in "${values[@]}"; do
                    echo "Value: $value"
                done
            fi
        fi
        found=1
    fi
    
    # Check with dcterms prefix
    local dcterms_value
    if dcterms_value=$(get_metadata_value "dcterms:$normalized_term"); then
        IFS=';' read -ra values <<< "$dcterms_value"
        
        # Handle select mode
        if [[ $DC_select_index -gt 0 ]]; then
            if [[ $DC_select_index -le ${#values[@]} ]]; then
                local selected_value="${values[$((DC_select_index-1))]}"
                if [[ $DC_clean_mode -eq 1 ]]; then
                    echo "$selected_value"
                else
                    echo "Term: dcterms:$term"
                    echo "Value: $selected_value"
                fi
            else
                if [[ $DC_clean_mode -eq 0 ]]; then
                    echo "Term 'dcterms:$term' has only ${#values[@]} value(s), cannot select position $DC_select_index"
                fi
                return 1
            fi
        else
            # Normal mode (all values)
            if [[ $DC_clean_mode -eq 1 ]]; then
                # Output values separated by semicolons
                echo "$dcterms_value"
            else
                echo "Term: dcterms:$term"
                for value in "${values[@]}"; do
                    echo "Value: $value"
                done
            fi
        fi
        found=1
    fi
    
    if [[ $found -eq 0 ]]; then
        if [[ $DC_clean_mode -eq 0 ]]; then
            echo "Term '$term' not found in metadata"
        fi
        return 1
    fi
    
    return 0
}

# ==============================================================================
# SUBSET OPERATION FUNCTIONS
# ==============================================================================

# Validate that selected terms exist in metadata
validate_DC_selected_terms() {
    set +o errexit  # Temporarily disable errexit for debugging
    local term normalized_term found_terms=0 missing_terms=()
    
    log_message "DEBUG" "Validating ${#DC_selected_terms[@]} selected terms"
    
    for term in "${DC_selected_terms[@]}"; do
        normalized_term="${term,,}"  # Convert to lowercase
        local term_found=0
        
        # Check direct match
        local direct_value
        if direct_value=$(get_metadata_value "$normalized_term" 2>/dev/null); then
            term_found=1
            log_message "DEBUG" "Found term: $term"
        fi
        
        # Check with dcterms prefix
        local dcterms_key="dcterms:$normalized_term"
        local dcterms_value
        if dcterms_value=$(get_metadata_value "$dcterms_key" 2>/dev/null); then
            term_found=1
            log_message "DEBUG" "Found dcterms term: $term"
        fi
        
        # Only count once per term
        if [[ $term_found -eq 1 ]]; then
            ((found_terms++))
        fi
        
        # If term not found, add to missing list
        if [[ $term_found -eq 0 ]]; then
            missing_terms+=("$term")
        fi
    done
    
    # Report results
    if [[ ${#missing_terms[@]} -gt 0 ]]; then
        local missing_list="${missing_terms[*]}"
        handle_error "WARNING" "Selected terms not found in metadata: ${missing_list// /, }"
        log_message "INFO" "Found $found_terms of ${#DC_selected_terms[@]} selected terms"
        
        # Don't fail the operation, just warn - allow partial subset creation
        if [[ $found_terms -eq 0 ]]; then
            handle_error "CRITICAL" "None of the selected terms were found in the metadata" 1
        fi
    else
        log_message "INFO" "All ${#DC_selected_terms[@]} selected terms found in metadata"
    fi
    
    set -o errexit  # Re-enable errexit
    return 0
}

# Filter metadata to include only selected terms
filter_metadata() {
    set +o errexit  # Temporarily disable errexit for array operations
    local term normalized_term
    
    # Clear existing filtered metadata
    if [[ ${#DC_filtered_metadata[@]} -gt 0 ]]; then
        for key in "${!DC_filtered_metadata[@]}"; do
            unset DC_filtered_metadata["$key"]
        done
    fi
    
    log_message "DEBUG" "Filtering metadata for ${#DC_selected_terms[@]} selected terms"
    
    for term in "${DC_selected_terms[@]}"; do
        normalized_term="${term,,}"  # Convert to lowercase
        
        # Check direct match and copy if found
        local direct_value
        if direct_value=$(get_metadata_value "$normalized_term" 2>/dev/null); then
            set_filtered_value "$normalized_term" "$direct_value"
            log_message "DEBUG" "Filtered term: $normalized_term"
        fi
        
        # Check with dcterms prefix and copy if found
        local dcterms_key="dcterms:$normalized_term"
        local dcterms_value
        if dcterms_value=$(get_metadata_value "$dcterms_key" 2>/dev/null); then
            set_filtered_value "$dcterms_key" "$dcterms_value"
            log_message "DEBUG" "Filtered dcterms term: $dcterms_key"
        fi
    done
    
    log_message "INFO" "Filtered ${#DC_filtered_metadata[@]} metadata entries"
    set -o errexit  # Re-enable errexit
    return 0
}

# Convert filtered metadata to XML format (subset)
convert_subset_to_xml() {
    local output="$1"
    local temp_file="${temp_dir}/output.xml"
    
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<metadata xmlns:dc="http://purl.org/dc/elements/1.1/"'
        echo '          xmlns:dcterms="http://purl.org/dc/terms/">'
        
        # Output filtered DC elements in the defined order
        for element in "${DC_ELEMENTS[@]}"; do
            if [[ -n "${DC_filtered_metadata[$element]:-}" ]]; then
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$element]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <dc:$element>$value</dc:$element>"
                done
            fi
        done
        
        # Output filtered DCTERMS elements
        for key in "${!DC_filtered_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$key]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <dcterms:$element>$value</dcterms:$element>"
                done
            fi
        done
        
        echo '</metadata>'
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "Subset XML output written to: $output"
    return 0
}

# Convert filtered metadata to text format (subset)
convert_subset_to_text() {
    local output="$1"
    local temp_file="${temp_dir}/output.txt"
    
    {
        echo "# Dublin Core Metadata (Subset)"
        echo "# Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Selected terms: ${DC_selected_terms[*]}"
        echo ""
        
        # Output filtered DC elements in the defined order
        for element in "${DC_ELEMENTS[@]}"; do
            if [[ -n "${DC_filtered_metadata[$element]:-}" ]]; then
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$element]}"
                for value in "${values[@]}"; do
                    # Capitalize first letter of element name
                    local display_name="${element^}"
                    echo "$display_name: $value"
                done
            fi
        done
        
        # Output filtered DCTERMS elements
        for key in "${!DC_filtered_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                local display_name="${element^}"
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$key]}"
                for value in "${values[@]}"; do
                    echo "$display_name: $value"
                done
            fi
        done
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "Subset text output written to: $output"
    return 0
}

# Convert filtered metadata to HTML format (subset)
convert_subset_to_html() {
    local output="$1"
    local temp_file="${temp_dir}/output.html"
    
    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en">'
        echo '<head>'
        echo '    <meta charset="UTF-8">'
        echo '    <title>Dublin Core Metadata (Subset)</title>'
        
        # Output filtered DC elements as meta tags
        for element in "${DC_ELEMENTS[@]}"; do
            if [[ -n "${DC_filtered_metadata[$element]:-}" ]]; then
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$element]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <meta name=\"DC.$element\" content=\"$value\">"
                done
            fi
        done
        
        # Output filtered DCTERMS elements as meta tags
        for key in "${!DC_filtered_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$key]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "    <meta name=\"dcterms.$element\" content=\"$value\">"
                done
            fi
        done
        
        echo '</head>'
        echo '<body>'
        echo '    <h1>Dublin Core Metadata (Subset)</h1>'
        echo "    <p><em>Selected terms: ${DC_selected_terms[*]}</em></p>"
        echo '    <dl>'
        
        # Output human-readable content for filtered DC elements
        for element in "${DC_ELEMENTS[@]}"; do
            if [[ -n "${DC_filtered_metadata[$element]:-}" ]]; then
                local display_name="${element^}"
                echo "        <dt><strong>$display_name:</strong></dt>"
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$element]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "        <dd>$value</dd>"
                done
            fi
        done
        
        # Output human-readable content for filtered DCTERMS elements
        for key in "${!DC_filtered_metadata[@]}"; do
            if [[ "$key" =~ ^dcterms: ]]; then
                local element="${key#dcterms:}"
                local display_name="${element^}"
                echo "        <dt><strong>$display_name (DCTERMS):</strong></dt>"
                IFS=';' read -ra values <<< "${DC_filtered_metadata[$key]}"
                for value in "${values[@]}"; do
                    value=$(escape_xml_chars "$value")
                    echo "        <dd>$value</dd>"
                done
            fi
        done
        
        echo '    </dl>'
        echo '    <footer>'
        echo "        <p><em>Generated: $(date '+%Y-%m-%d %H:%M:%S')</em></p>"
        echo '    </footer>'
        echo '</body>'
        echo '</html>'
    } > "$temp_file"
    
    # Move to final location
    mv "$temp_file" "$output"
    
    log_message "INFO" "Subset HTML output written to: $output"
    return 0
}

# ==============================================================================
# DISPLAY FUNCTIONS
# ==============================================================================

# Display all metadata
display_metadata() {
    echo "=== Dublin Core Metadata ==="
    echo "File: $DC_input_file"
    echo ""
    
    local has_metadata=0
    
    # Display DC elements
    for element in "${DC_ELEMENTS[@]}"; do
        local element_value
        if element_value=$(get_metadata_value "$element" 2>/dev/null); then
            has_metadata=1
            local display_name="${element^}"
            echo "$display_name:"
            IFS=';' read -ra values <<< "$element_value"
            for value in "${values[@]}"; do
                echo "  - $value"
            done
        fi
    done
    
    # Display DCTERMS elements
    local all_keys
    all_keys=$(get_metadata_keys)
    while IFS= read -r key; do
        if [[ "$key" =~ ^dcterms: ]]; then
            has_metadata=1
            local element="${key#dcterms:}"
            local display_name="${element^}"
            echo "$display_name (DCTERMS):"
            local key_value
            if key_value=$(get_metadata_value "$key" 2>/dev/null); then
                IFS=';' read -ra values <<< "$key_value"
                for value in "${values[@]}"; do
                    echo "  - $value"
                done
            fi
        fi
    done <<< "$all_keys"
    
    if [[ $has_metadata -eq 0 ]]; then
        echo "No Dublin Core metadata found in file"
    fi
}

# Display help information
display_help() {
    cat << EOF
Dublin Core Metadata Processing Script v${SCRIPT_VERSION}

USAGE:
    ${SCRIPT_NAME} [OPTIONS]

OPTIONS:
    --help, -h          Display this help message
    --read, -r FILE     Read and display Dublin Core metadata from FILE
    --validate, -v      Validate Dublin Core metadata (use with --read)
    --format, -f FORMAT --output, -o FILE    Convert metadata to FORMAT and write to FILE (xml, text, html)
                                         (--format and --output must be used together)
    --term, -t TERM     Extract specific Dublin Core term OR select term for subset operation
                        (can be used multiple times for subset creation or create mode)
    --clean, -l         Output only term values, semicolon-separated if multiple (use with single --term)
    --select, -s N      Select Nth value when term has multiple values (1-based index, use with single --term)
                        Syntax: --term TERM --select N --read FILE
    --create, -c        Create new Dublin Core file from --term flags (no input file required)
    --verbose, -V       Enable verbose output
    --debug, -d         Enable debug output

OPERATION MODES:
    1. Read Mode:       Display all metadata from input file
    2. Validate Mode:   Check Dublin Core compliance
    3. Convert Mode:    Transform entire file between formats
    4. Extract Mode:    Get values for a single term (single --term only)
    5. Subset Mode:     Create new file with only selected terms (multiple --term with --format)
    6. Create Mode:     Create new Dublin Core file from scratch (--create with --term flags)

EXAMPLES:
    # Read and display metadata
    ${SCRIPT_NAME} --read metadata.xml

    # Validate Dublin Core compliance
    ${SCRIPT_NAME} --validate --read metadata.xml

    # Convert between formats
    ${SCRIPT_NAME} --read metadata.txt --format xml --output metadata.xml
    ${SCRIPT_NAME} --read metadata.xml --format html --output metadata.html
    ${SCRIPT_NAME} --read metadata.html --format text --output metadata.txt

    # Extract specific term
    ${SCRIPT_NAME} --term "title" --read metadata.xml
    ${SCRIPT_NAME} --term "creator" --read metadata.txt
    
    # Extract term with clean output (values only, semicolon-separated if multiple)
    ${SCRIPT_NAME} --term "title" --clean --read metadata.xml
    ${SCRIPT_NAME} --term "creator" --clean --read metadata.xml  # Multiple values: "Smith, Jane;Johnson, Bob"
    
    # Select specific term value by position (1-based index)
    ${SCRIPT_NAME} --term "creator" --select 1 --read metadata.xml          # Gets first creator value
    ${SCRIPT_NAME} --term "creator" --select 2 --read metadata.xml          # Gets second creator value  
    ${SCRIPT_NAME} --term "creator" --select 2 --clean --read metadata.xml  # Gets second creator, clean output
    ${SCRIPT_NAME} --term "identifier" --select 1 --clean --read metadata.xml  # Gets first identifier, values only

    # Create subset files with multiple terms (NEW FEATURE)
    ${SCRIPT_NAME} --read input.xml --term title --term creator --format xml --output subset.xml
    ${SCRIPT_NAME} --read input.xml --term title --term date --term publisher --format text --output subset.txt
    ${SCRIPT_NAME} --read input.xml --term abstract --term license --format html --output subset.html
    
    # Multiple terms with verbose output for debugging
    ${SCRIPT_NAME} --read input.xml --term title --term creator --term subject --format xml --output subset.xml --verbose
    
    # Create new Dublin Core files from scratch (create mode)
    ${SCRIPT_NAME} --create --term title \"My Document\" --term creator \"John Doe\" --format xml --output new.xml
    ${SCRIPT_NAME} --create --term title \"Research Paper\" --term date \"2024-01-15\" --term publisher \"Academic Press\" --format text --output new.txt
    ${SCRIPT_NAME} --create --term title \"Web Resource\" --term abstract \"Summary text\" --format html --output new.html

SUPPORTED FORMATS:
    - XML:  Dublin Core XML with dc: and dcterms: namespaces
    - Text: Simple key: value format
    - HTML: Meta tags with DC. and dcterms. prefixes

DUBLIN CORE 1.1 ELEMENTS (15):
    title, creator, subject, description, publisher, contributor,
    date, type, format, identifier, source, language, relation,
    coverage, rights

DCMI TERMS (Extended Elements):
    abstract, accessRights, alternative, audience, available, 
    bibliographicCitation, conformsTo, created, extent, hasVersion,
    instructionalMethod, issued, license, mediator, medium, modified,
    provenance, rightsHolder, spatial, tableOfContents, temporal, valid

NAMESPACE PREFIXES:
    dc:       Dublin Core 1.1 elements (http://purl.org/dc/elements/1.1/)
    dcterms:  DCMI Terms (http://purl.org/dc/terms/)

TERM USAGE:
    Use element names without prefixes in --term flags (e.g., --term title, --term abstract)
    Script automatically detects appropriate namespace (dc: or dcterms:)
    All terms support multiple values separated by semicolon (;) character

Download the latest version of ${SCRIPT_NAME} at:
    https://github.com/Qirab/dublincore-bash

For more information about Dublin Core, visit:
    https://www.dublincore.org/

EOF
}

# ==============================================================================
# MAIN FUNCTIONS
# ==============================================================================

# Parse command-line arguments
parse_arguments() {
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
                DC_input_file="$1"
                shift
                ;;
            --validate|-v)
                DC_operation="validate"
                shift
                ;;
            --format|-f)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing format argument for --format" 1
                fi
                DC_target_format="$1"
                # Validate format
                if [[ ! "$DC_target_format" =~ ^(xml|text|html)$ ]]; then
                    handle_error "CRITICAL" "Invalid format: $DC_target_format (must be xml, text, or html)" 1
                fi
                shift
                
                # --format must be immediately followed by --output
                if [[ -z "${1:-}" ]] || [[ "$1" != "--output" && "$1" != "-o" ]]; then
                    handle_error "CRITICAL" "--format must be immediately followed by --output: --format xml --output file.xml" 1
                fi
                
                # Parse the --output flag
                shift  # Skip --output/-o
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing file argument for --output" 1
                fi
                DC_output_file="$1"
                
                # Set operation based on context
                if [[ $DC_create_mode -eq 1 ]]; then
                    # Create mode takes precedence
                    DC_operation="create"
                elif [[ ${#DC_selected_terms[@]} -gt 0 ]]; then
                    # Terms already specified, this is subset mode
                    DC_operation="subset"
                    DC_subset_mode=1
                else
                    # No terms yet, regular conversion
                    DC_operation="convert"
                fi
                
                shift
                ;;
            --output|-o)
                # --output should only be used when --format is not available
                # With --format, --output is parsed together automatically
                if [[ -z "$DC_target_format" ]]; then
                    handle_error "CRITICAL" "--output requires --format to be specified first: --format xml --output file.xml" 1
                fi
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing file argument for --output" 1
                fi
                DC_output_file="$1"
                shift
                ;;
            --term|-t)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --term" 1
                fi
                
                # Handle create mode vs other modes differently
                if [[ $DC_create_mode -eq 1 ]] || [[ "$DC_operation" == "create" ]]; then
                    # In create mode, expect term name followed by value
                    local key="$1"
                    key=$(trim "$key")
                    key="${key,,}"  # Convert to lowercase
                    
                    # Get the value from the next argument
                    shift
                    if [[ $# -eq 0 ]] || [[ "$1" == --* ]]; then
                        handle_error "CRITICAL" "In create mode, --term requires value argument: --term title \"My Title\"" 1
                    fi
                    local value="$1"
                    value=$(trim "$value")
                    
                    # Check if it's a DCTERMS element (not in DC_ELEMENTS)
                    local is_dc_element=0
                    for dc_elem in "${DC_ELEMENTS[@]}"; do
                        if [[ "$key" == "$dc_elem" ]]; then
                            is_dc_element=1
                            break
                        fi
                    done
                    
                    # If not a DC element, check if it's a valid DCTERMS element
                    if [[ $is_dc_element -eq 0 ]]; then
                        local is_dcterms_element=0
                        for dcterm_elem in "${DCTERMS_ELEMENTS[@]}"; do
                            if [[ "$key" == "$dcterm_elem" ]]; then
                                key="dcterms:$key"
                                is_dcterms_element=1
                                break
                            fi
                        done
                        
                        # If neither DC nor DCTERMS, still allow (user may know additional terms)
                        if [[ $is_dcterms_element -eq 0 ]]; then
                            log_message "WARNING" "Unknown Dublin Core term: $key (proceeding anyway)"
                        fi
                    fi
                    
                    # Store the key=value pair in DC_metadata for write mode
                    append_metadata_value "$key" "$value"
                    
                    # Also add to DC_selected_terms for tracking
                    DC_selected_terms+=("$key")
                else
                    # Traditional mode: just add term name to DC_selected_terms array
                    DC_selected_terms+=("$1")
                    
                    # Set operation based on context (but don't override create mode)
                    if [[ -z "$DC_operation" ]] && [[ $DC_create_mode -eq 0 ]]; then
                        # First --term encountered and not in create mode
                        if [[ -n "${DC_target_format:-}" ]]; then
                            # If --format was already specified, this is subset mode
                            DC_operation="subset"
                            DC_subset_mode=1
                        else
                            # Traditional single term extraction
                            DC_operation="extract"
                            DC_term_name="$1"
                        fi
                    elif [[ "$DC_operation" == "extract" ]]; then
                        # Second --term encountered, switch to subset mode
                        DC_operation="subset"
                        DC_subset_mode=1
                        # Clear DC_term_name as we now use DC_selected_terms
                        DC_term_name=""
                    elif [[ "$DC_operation" == "convert" ]]; then
                        # --format was specified first, this becomes subset mode
                        DC_operation="subset"
                        DC_subset_mode=1
                    fi
                fi
                
                shift
                ;;
            --create|-c)
                DC_create_mode=1
                DC_operation="create"
                shift
                ;;
            --clean|-l)
                DC_clean_mode=1
                shift
                ;;
            --select|-s)
                shift
                if [[ -z "${1:-}" ]]; then
                    handle_error "CRITICAL" "Missing argument for --select" 1
                fi
                if ! [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
                    handle_error "CRITICAL" "Invalid --select value: '$1' (must be a positive integer starting from 1)" 1
                fi
                DC_select_index="$1"
                shift
                ;;
            --verbose|-V)
                DC_verbose=1
                shift
                ;;
            --debug|-d)
                DC_debug=1
                DC_verbose=1
                shift
                ;;
            *)
                handle_error "CRITICAL" "Unknown option: $1" 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$DC_input_file" ]] && [[ "$DC_operation" != "create" ]]; then
        handle_error "CRITICAL" "No input file specified. Use --read FILE" 1
    fi
    
    # Set default operation if none specified
    if [[ -z "$DC_operation" ]]; then
        if [[ $DC_create_mode -eq 1 ]]; then
            DC_operation="create"
        else
            DC_operation="read"
        fi
    fi
    
    # Validate convert operation requirements
    if [[ "$DC_operation" == "convert" ]] && [[ -z "$DC_output_file" ]]; then
        handle_error "CRITICAL" "No output file specified for conversion. Use --output FILE" 1
    fi
    
    # Validate subset operation requirements
    if [[ "$DC_operation" == "subset" ]]; then
        if [[ ${#DC_selected_terms[@]} -eq 0 ]]; then
            handle_error "CRITICAL" "No terms specified for subset operation. Use --term TERM" 1
        fi
        if [[ -z "$DC_target_format" ]]; then
            handle_error "CRITICAL" "No output format specified for subset operation. Use --format FORMAT" 1
        fi
        if [[ -z "$DC_output_file" ]]; then
            handle_error "CRITICAL" "No output file specified for subset operation. Use --output FILE" 1
        fi
    fi
    
    # Validate create operation requirements
    if [[ "$DC_operation" == "create" ]]; then
        if [[ ${#DC_selected_terms[@]} -eq 0 ]]; then
            handle_error "CRITICAL" "No terms specified for create operation. Use --term KEY VALUE" 1
        fi
        if [[ -z "$DC_target_format" ]]; then
            handle_error "CRITICAL" "No output format specified for create operation. Use --format FORMAT" 1
        fi
        if [[ -z "$DC_output_file" ]]; then
            handle_error "CRITICAL" "No output file specified for create operation. Use --output FILE" 1
        fi
    fi
}

# Execute the requested operation
execute_operation() {
    local format
    
    # Only validate and parse input file if not in create mode
    if [[ "$DC_operation" != "create" ]]; then
        # Validate input file
        validate_file_security "$DC_input_file"
        
        # Detect format
        format=$(detect_format "$DC_input_file")
        log_message "INFO" "Detected format: $format"
        
        # Parse the input file
        case "$format" in
            xml)
                parse_xml "$DC_input_file"
                ;;
            html)
                parse_html "$DC_input_file"
                ;;
            text)
                parse_text "$DC_input_file"
                ;;
            *)
                handle_error "CRITICAL" "Unknown format: $format" 1
                ;;
        esac
    else
        log_message "INFO" "Create mode: creating new Dublin Core file from provided terms"
    fi
    
    # Execute the operation
    case "$DC_operation" in
        read)
            display_metadata
            ;;
        validate)
            validate_dublin_core "$format"
            ;;
        convert)
            case "$DC_target_format" in
                xml)
                    convert_to_xml "$DC_output_file"
                    ;;
                text)
                    convert_to_text "$DC_output_file"
                    ;;
                html)
                    convert_to_html "$DC_output_file"
                    ;;
            esac
            ;;
        extract)
            extract_term "$DC_term_name"
            ;;
        subset)
            # Validate that selected terms exist in metadata
            validate_DC_selected_terms
            
            # Filter metadata to only include selected terms
            filter_metadata
            
            # Convert filtered metadata to the specified format
            case "$DC_target_format" in
                xml)
                    convert_subset_to_xml "$DC_output_file"
                    ;;
                text)
                    convert_subset_to_text "$DC_output_file"
                    ;;
                html)
                    convert_subset_to_html "$DC_output_file"
                    ;;
            esac
            ;;
        create)
            # Create mode: use existing conversion functions with DC_metadata populated from --term flags
            case "$DC_target_format" in
                xml)
                    convert_to_xml "$DC_output_file"
                    ;;
                text)
                    convert_to_text "$DC_output_file"
                    ;;
                html)
                    convert_to_html "$DC_output_file"
                    ;;
            esac
            ;;
        *)
            handle_error "CRITICAL" "Unknown operation: $operation" 1
            ;;
    esac
}

# Main function
main() {
    # Create temp directory
    temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'dublincore')
    
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
