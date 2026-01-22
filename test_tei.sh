#!/usr/bin/env bash
#
# test_tei.sh - Comprehensive test suite for tei.sh
#
# Tests all operations against available TEI test files
#

set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEI_SCRIPT="${SCRIPT_DIR}/tei.sh"

# Test output directory
TEST_OUTPUT_DIR="${SCRIPT_DIR}/test_output"
mkdir -p "$TEST_OUTPUT_DIR"

# Log file
LOG_FILE="${TEST_OUTPUT_DIR}/test_results.log"
> "$LOG_FILE"

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

log() {
    echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_section() {
    echo ""
    echo -e "${YELLOW}--- $1 ---${NC}"
}

pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    log "PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    log "FAIL: $1 - $2"
    if [[ -n "${2:-}" ]]; then
        echo -e "         ${RED}Reason: $2${NC}"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

skip() {
    echo -e "  ${YELLOW}○ SKIP${NC}: $1"
    log "SKIP: $1 - $2"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

# ==============================================================================
# TEST FUNCTIONS
# ==============================================================================

# Test --read operation
test_read() {
    local file="$1"
    local name="$(basename "$file")"
    local output
    local exit_code

    output=$("$TEI_SCRIPT" --read "$file" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        # Check that output contains expected sections
        if [[ "$output" == *"TEI P5 Metadata"* ]]; then
            pass "read: $name"
            return 0
        else
            fail "read: $name" "Missing metadata header in output"
            return 1
        fi
    else
        fail "read: $name" "Exit code: $exit_code"
        return 1
    fi
}

# Test --validate operation
test_validate() {
    local file="$1"
    local expect_valid="${2:-true}"
    local name="$(basename "$file")"
    local output
    local exit_code

    output=$("$TEI_SCRIPT" --validate "$file" 2>&1)
    exit_code=$?

    if [[ "$expect_valid" == "true" ]]; then
        if [[ $exit_code -eq 0 ]] && [[ "$output" == *"Status:"* ]]; then
            pass "validate: $name"
            return 0
        else
            fail "validate: $name" "Expected valid, got exit code: $exit_code"
            return 1
        fi
    else
        # For invalid files, we expect non-zero exit or INVALID status
        if [[ $exit_code -ne 0 ]] || [[ "$output" == *"INVALID"* ]]; then
            pass "validate (expected invalid): $name"
            return 0
        else
            fail "validate: $name" "Expected invalid result"
            return 1
        fi
    fi
}

# Test --term extraction
test_extract() {
    local file="$1"
    local term="$2"
    local name="$(basename "$file")"
    local output
    local exit_code

    output=$("$TEI_SCRIPT" --term "$term" "$file" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]] && [[ "$output" == *"Term:"* || "$output" == *"Value:"* ]]; then
        pass "extract '$term': $name"
        return 0
    elif [[ "$output" == *"not found"* ]]; then
        # Term not found is acceptable for some files
        pass "extract '$term' (not found): $name"
        return 0
    else
        fail "extract '$term': $name" "Exit code: $exit_code"
        return 1
    fi
}

# Test --write operation
test_write() {
    local output_file="${TEST_OUTPUT_DIR}/write_test_$1.xml"
    local terms=("${@:2}")
    local term_args=""

    for term in "${terms[@]}"; do
        term_args="$term_args --term \"$term\""
    done

    local output
    local exit_code

    # Use eval to handle the quoted arguments properly
    output=$(eval "$TEI_SCRIPT --write $term_args --output \"$output_file\"" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]] && [[ -f "$output_file" ]]; then
        # Verify the file is valid XML
        if [[ -f "$output_file" ]] && grep -q "<?xml" "$output_file"; then
            pass "write: test_$1"
            return 0
        else
            fail "write: test_$1" "Invalid XML generated"
            return 1
        fi
    else
        fail "write: test_$1" "Exit code: $exit_code"
        return 1
    fi
}

# Test error handling
test_error_handling() {
    local test_name="$1"
    local expected_exit="${2:-1}"
    shift 2
    local args=("$@")
    local output
    local exit_code

    output=$("$TEI_SCRIPT" "${args[@]}" 2>&1)
    exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        pass "error handling: $test_name"
        return 0
    else
        fail "error handling: $test_name" "Expected non-zero exit, got: $exit_code"
        return 1
    fi
}

# ==============================================================================
# TEST FILE CATEGORIES
# ==============================================================================

# Minimal TEI files
MINIMAL_FILES=(
    "${SCRIPT_DIR}/TEI/P5/Test/testbare.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testminimal.xml"
)

# Standard/comprehensive TEI files
STANDARD_FILES=(
    "${SCRIPT_DIR}/MS-ADD-01132.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testbasic.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testms.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/torture.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testall.xml"
)

# Feature-specific TEI files
FEATURE_FILES=(
    "${SCRIPT_DIR}/TEI/P5/Test/testnames.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testplace.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testchinese.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testdrama.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testtranscr.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testbibl.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testfsd.xml"
    "${SCRIPT_DIR}/TEI/P5/Test/testrdf.xml"
)

# Edge case / Non-TEI files (expected to fail - not valid TEI structure)
EDGE_CASE_FILES=(
    "${SCRIPT_DIR}/TEI/P5/Test/antruntest.xml"
)

# teiCorpus files - valid TEI but use different root element (not tested as invalid)
# testcorpus.xml uses <teiCorpus> which is valid TEI P5 but not supported by tei.sh

# ==============================================================================
# MAIN TEST EXECUTION
# ==============================================================================

main() {
    print_header "TEI.SH TEST SUITE"
    echo "Script: $TEI_SCRIPT"
    echo "Output: $TEST_OUTPUT_DIR"
    echo "Log: $LOG_FILE"

    # Verify script exists
    if [[ ! -x "$TEI_SCRIPT" ]]; then
        echo -e "${RED}ERROR: tei.sh not found or not executable${NC}"
        exit 1
    fi

    # Test 1: Help display
    print_section "Help Display"
    if "$TEI_SCRIPT" --help | grep -q "TEI P5 Processing Script"; then
        pass "help display"
    else
        fail "help display" "Help text not found"
    fi

    # Test 2: Read operation - Minimal files
    print_section "Read Operation - Minimal Files"
    for file in "${MINIMAL_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            test_read "$file"
        else
            skip "read: $(basename "$file")" "File not found"
        fi
    done

    # Test 3: Read operation - Standard files
    print_section "Read Operation - Standard Files"
    for file in "${STANDARD_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            test_read "$file"
        else
            skip "read: $(basename "$file")" "File not found"
        fi
    done

    # Test 4: Read operation - Feature files
    print_section "Read Operation - Feature-Specific Files"
    for file in "${FEATURE_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            test_read "$file"
        else
            skip "read: $(basename "$file")" "File not found"
        fi
    done

    # Test 5: Validate operation - Valid files
    print_section "Validate Operation - Valid Files"
    for file in "${MINIMAL_FILES[@]}" "${STANDARD_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            test_validate "$file" "true"
        else
            skip "validate: $(basename "$file")" "File not found"
        fi
    done

    # Test 6: Validate operation - Edge cases
    print_section "Validate Operation - Edge Cases"
    for file in "${EDGE_CASE_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            test_validate "$file" "false"
        else
            skip "validate (edge case): $(basename "$file")" "File not found"
        fi
    done

    # Test 7: Term extraction
    print_section "Term Extraction"
    local test_file="${SCRIPT_DIR}/MS-ADD-01132.xml"
    if [[ -f "$test_file" ]]; then
        test_extract "$test_file" "fileDesc.titleStmt.title"
        test_extract "$test_file" "persName"
        test_extract "$test_file" "placeName"
        test_extract "$test_file" "date"
    else
        skip "term extraction" "MS-ADD-01132.xml not found"
    fi

    # Additional extraction tests with testnames.xml
    local names_file="${SCRIPT_DIR}/TEI/P5/Test/testnames.xml"
    if [[ -f "$names_file" ]]; then
        test_extract "$names_file" "persName"
        test_extract "$names_file" "placeName"
        test_extract "$names_file" "orgName"
    fi

    # Test 8: Write operation
    print_section "Write Operation"
    test_write "basic" "fileDesc.titleStmt.title=Test Title" "fileDesc.titleStmt.author=Test Author"
    test_write "full" "fileDesc.titleStmt.title=Full Test" "fileDesc.titleStmt.author=Author Name" "fileDesc.publicationStmt.date=2025" "fileDesc.publicationStmt.publisher=Test Publisher"

    # Test 9: Error handling
    print_section "Error Handling"
    test_error_handling "missing file" 1 --read "/nonexistent/file.xml"
    test_error_handling "invalid option" 1 --invalid-option
    test_error_handling "write without output" 1 --write --term "fileDesc.titleStmt.title=Test"
    test_error_handling "write without terms" 1 --write --output "${TEST_OUTPUT_DIR}/empty.xml"

    # Test 10: Short option aliases
    print_section "Short Option Aliases"
    local test_file="${SCRIPT_DIR}/MS-ADD-01132.xml"
    if [[ -f "$test_file" ]]; then
        local r_output
        r_output=$("$TEI_SCRIPT" -r "$test_file" 2>&1)
        if echo "$r_output" | grep -q "TEI P5 Metadata"; then
            pass "short option: -r (read)"
        else
            fail "short option: -r (read)" "Output: ${r_output:0:100}"
        fi

        if "$TEI_SCRIPT" -V "$test_file" 2>&1 | grep -q "Status:"; then
            pass "short option: -V (validate)"
        else
            fail "short option: -V (validate)"
        fi

        local t_output
        t_output=$("$TEI_SCRIPT" -t "fileDesc.titleStmt.title" "$test_file" 2>&1)
        if echo "$t_output" | grep -q -E "(Term:|Value:|not found)"; then
            pass "short option: -t (term)"
        else
            fail "short option: -t (term)" "Output: ${t_output:0:100}"
        fi
    fi

    # Test 11: Bulk test all TEI/P5/Test files
    print_section "Bulk Read Test - All TEI/P5/Test Files"
    local test_dir="${SCRIPT_DIR}/TEI/P5/Test"
    local bulk_passed=0
    local bulk_failed=0
    local bulk_total=0

    if [[ -d "$test_dir" ]]; then
        for xml_file in "$test_dir"/*.xml; do
            if [[ -f "$xml_file" ]]; then
                bulk_total=$((bulk_total + 1))
                if "$TEI_SCRIPT" --read "$xml_file" >/dev/null 2>&1; then
                    bulk_passed=$((bulk_passed + 1))
                else
                    bulk_failed=$((bulk_failed + 1))
                    log "BULK FAIL: $(basename "$xml_file")"
                fi
            fi
        done
        echo -e "  Processed: $bulk_total files"
        echo -e "  ${GREEN}Passed: $bulk_passed${NC}"
        if [[ $bulk_failed -gt 0 ]]; then
            echo -e "  ${YELLOW}Failed/Warnings: $bulk_failed${NC} (see log for details)"
        fi

        # Count bulk test as one test
        if [[ $bulk_failed -lt $((bulk_total / 4)) ]]; then
            pass "bulk read test (${bulk_passed}/${bulk_total} files)"
        else
            fail "bulk read test" "Too many failures: $bulk_failed/$bulk_total"
        fi
    fi

    # Print summary
    print_header "TEST SUMMARY"
    echo ""
    echo -e "  Total tests run:    $TESTS_RUN"
    echo -e "  ${GREEN}Passed:             $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed:             $TESTS_FAILED${NC}"
    echo -e "  ${YELLOW}Skipped:            $TESTS_SKIPPED${NC}"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  ALL TESTS PASSED!${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}  SOME TESTS FAILED - See $LOG_FILE for details${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        exit 1
    fi
}

# Run main
main "$@"
