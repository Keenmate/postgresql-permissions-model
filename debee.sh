#!/usr/bin/env bash

# Debee - PostgreSQL Migration Orchestrator (Bash Version)
# Pure orchestration script - all database logic lives in external SQL files

DEBEE_VERSION="1.1.0"

set -e  # Exit on error

# Default values
ENVIRONMENT=""
OPERATIONS=("fullService")
UPDATE_START_NUMBER=-1
UPDATE_END_NUMBER=-1
SQL_FILE=""
SQL_COMMAND=""
TEST_FILTER="all"
TEST_VERBOSE=false
SILENT=false
ASSUME_YES=false

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_error() {
    echo -e "${RED}Error: $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}Warning: $1${NC}"
}

print_success() {
    [[ "$SILENT" == true ]] && return 0
    echo -e "${GREEN}$1${NC}"
}

print_info() {
    [[ "$SILENT" == true ]] && return 0
    echo "$1"
}

# Set environment variable
set_env_var() {
    local key=$1
    local value=$2
    export "$key=$value"
}

# Prepare environment from .env file
prepare_environment() {
    local env_file=$1

    if [[ -f "$env_file" ]]; then
        print_info "Loading environment from $env_file"

        # Read file line by line
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            if [[ -z "$line" ]] || [[ "$line" =~ ^[[:space:]]*# ]]; then
                continue
            fi

            # Check if line contains =
            if [[ "$line" == *"="* ]]; then
                # Extract key and value
                key="${line%%=*}"
                value="${line#*=}"

                # Remove leading/trailing whitespace
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | xargs)

                # Remove quotes if present
                value="${value%\"}"
                value="${value#\"}"
                value="${value%\'}"
                value="${value#\'}"

                # Set environment variable
                set_env_var "$key" "$value"
            else
                print_warning "Skipping invalid line: $line"
            fi
        done < "$env_file"

        print_success "Environment variables set successfully from $env_file"
    else
        print_error "File not found: $env_file"
        return 1
    fi
}

# Set current database
set_current_database() {
    local database_name=$1
    set_env_var "PGDATABASE" "$database_name"
}

# Get files by numeric prefix
get_files_by_numeric_prefix() {
    local start_num=$1
    local end_num=$2

    local range_text
    if [[ $start_num -eq -1 && $end_num -eq -1 ]]; then
        range_text="all"
    elif [[ $end_num -eq -1 ]]; then
        range_text="${start_num} onwards"
    elif [[ $start_num -eq -1 ]]; then
        range_text="up to ${end_num}"
    else
        range_text="${start_num} -> ${end_num}"
    fi
    print_warning "Scripts to run: ${range_text}"

    # Validate range
    if [[ $start_num -gt $end_num ]] && [[ $end_num -ne -1 ]]; then
        print_error "StartNumber ($start_num) cannot be greater than EndNumber ($end_num)."
        return 1
    fi

    # Find matching files
    local matching_files=()

    for file in [0-9][0-9][0-9]_*; do
        if [[ ! -f "$file" ]]; then
            continue
        fi

        # Extract numeric prefix
        prefix="${file:0:3}"
        prefix=$((10#$prefix))  # Convert to decimal (remove leading zeros)

        # Check if within range
        if { [[ $prefix -ge $start_num ]] || [[ $start_num -eq -1 ]]; } && \
           { [[ $prefix -le $end_num ]] || [[ $end_num -eq -1 ]]; }; then
            print_info "File: $file is within the update range."
            matching_files+=("$file")
        fi
    done

    print_info "Number of matching files: ${#matching_files[@]}"

    # Return files (as string, separated by newlines)
    printf '%s\n' "${matching_files[@]}"
}

# Recreate database
recreate_database() {
    set_current_database "$DBCONNECTDB"

    print_info "Recreating database on host: $PGHOST, connected to: $PGDATABASE"

    if [[ -z "$DBRECREATESCRIPT" ]] || [[ ! -f "$DBRECREATESCRIPT" ]]; then
        print_error "Recreation script not found: $DBRECREATESCRIPT"
        return 1
    fi

    $DBPSQLFILE -f "$DBRECREATESCRIPT"
}

# Restore database
restore_database() {
    local backup_filepath="${1:-$DBBACKUPFILE}"
    local backup_type="${2:-$DBBACKUPTYPE}"

    print_info "Calculating backup type and path"

    if [[ -z "$backup_filepath" ]]; then
        print_warning "No restore file defined, skipping"
        return 0
    fi

    local job_count=1
    if [[ -n "$DBRESTOREJOBCOUNT" ]] && [[ $DBRESTOREJOBCOUNT -gt 0 ]]; then
        job_count=$DBRESTOREJOBCOUNT
    fi

    print_warning "Restoring database with $job_count jobs"

    case "$backup_type" in
        "file")
            print_info "Restoring from file: $backup_filepath"
            set_current_database "$DBDESTDB"
            $DBPSQLFILE -f "$backup_filepath"
            ;;
        "dir")
            print_info "Restoring from directory: $backup_filepath"
            set_current_database "$DBDESTDB"

            if [[ "$DBCREATEONRESTORE" == "true" ]]; then
                $DBPGRESTOREFILE -v -F d -C -d "$DBCONNECTDB" "$backup_filepath"
            else
                $DBPGRESTOREFILE -v -F d -d "$DBDESTDB" "$backup_filepath"
            fi
            ;;
        "custom")
            print_info "Restoring from custom archive: $backup_filepath"
            set_current_database "$DBDESTDB"

            if [[ "$DBCREATEONRESTORE" == "true" ]]; then
                $DBPGRESTOREFILE -v -F c -C -d "$DBCONNECTDB" "$backup_filepath"
            else
                $DBPGRESTOREFILE -v -F c -d "$DBDESTDB" "$backup_filepath"
            fi
            ;;
        *)
            print_error "Unknown backup type: $backup_type"
            return 1
            ;;
    esac
}

# Update database with files
update_database_with_files() {
    print_info "Updating database..."
    set_current_database "$DBDESTDB"

    # Process files passed as arguments
    for file in "$@"; do
        if [[ -f "$file" ]] && [[ -s "$file" ]]; then
            print_info ".. with file: $file"
            $DBPSQLFILE -q -b -n --csv -f "$file"
        fi
    done
}

# Update database
update_database() {
    # Get files and store in array
    mapfile -t files < <(get_files_by_numeric_prefix "$UPDATE_START_NUMBER" "$UPDATE_END_NUMBER")

    print_info "Number of returned files: ${#files[@]}"

    if [[ ${#files[@]} -gt 0 ]]; then
        # Sort files and update database
        IFS=$'\n' sorted_files=($(sort <<<"${files[*]}"))
        unset IFS

        update_database_with_files "${sorted_files[@]}"
    fi
}

# Run pre-update scripts
run_pre_update_scripts() {
    if [[ -z "$DBPREUPDATESCRIPTS" ]]; then
        print_info "No pre-update scripts, skipping the step"
        return 0
    fi

    # Split scripts by semicolon
    IFS=';' read -ra scripts <<< "$DBPREUPDATESCRIPTS"

    local scripts_to_run=()

    for script in "${scripts[@]}"; do
        # Trim whitespace
        script=$(echo "$script" | xargs)

        if [[ -f "$script" ]]; then
            scripts_to_run+=("$script")
            print_info "Pre-update script file: $script to be run."
        else
            print_warning "File does not exist: $script"
        fi
    done

    if [[ ${#scripts_to_run[@]} -gt 0 ]]; then
        update_database_with_files "${scripts_to_run[@]}"
    fi
}

# Run post-update scripts
run_post_update_scripts() {
    if [[ -z "$DBPOSTUPDATESCRIPTS" ]]; then
        print_info "No post-update scripts, skipping the step"
        return 0
    fi

    # Split scripts by semicolon
    IFS=';' read -ra scripts <<< "$DBPOSTUPDATESCRIPTS"

    local scripts_to_run=()

    for script in "${scripts[@]}"; do
        # Trim whitespace
        script=$(echo "$script" | xargs)

        if [[ -z "$script" ]]; then
            print_warning "Post-update script path empty, skipping"
            continue
        fi

        if [[ -f "$script" ]]; then
            scripts_to_run+=("$script")
            print_info "Post-update script file: $script to be run."
        else
            print_warning "File does not exist: $script"
        fi
    done

    if [[ ${#scripts_to_run[@]} -gt 0 ]]; then
        update_database_with_files "${scripts_to_run[@]}"
    fi
}

# Prepare version table
prepare_version_table() {
    print_info "Preparing version table - extracting database objects"

    # Get configuration values
    local formats_str="${DBVERSIONTABLEFORMATS:-json;md}"
    local output_folder="${DBVERSIONTABLEOUTPUTFOLDER:-.}"
    local base_filename="${DBVERSIONTABLEFILENAME:-db-objects}"

    # Remove comments from formats string (anything after #)
    formats_str="${formats_str%%#*}"
    formats_str="${formats_str%% }"  # trim trailing spaces

    # Parse formats
    IFS=';' read -ra formats_array <<< "$formats_str"
    local formats=()
    for fmt in "${formats_array[@]}"; do
        fmt=$(echo "$fmt" | tr '[:upper:]' '[:lower:]' | xargs)  # trim and lowercase
        if [[ -n "$fmt" ]]; then
            formats+=("$fmt")
        fi
    done

    if [[ ${#formats[@]} -eq 0 ]]; then
        print_warning "No version table formats specified, using default: json, md"
        formats=("json" "md")
    fi

    # Validate formats
    local valid_formats=("json" "md" "markdown" "csv" "html")
    local invalid_formats=()
    for fmt in "${formats[@]}"; do
        local valid=false
        for valid_fmt in "${valid_formats[@]}"; do
            if [[ "$fmt" == "$valid_fmt" ]]; then
                valid=true
                break
            fi
        done
        if [[ "$valid" == false ]]; then
            invalid_formats+=("$fmt")
        fi
    done

    if [[ ${#invalid_formats[@]} -gt 0 ]]; then
        print_error "Invalid formats: ${invalid_formats[*]}. Valid formats: json, md, csv, html"
        return 1
    fi

    # Normalize markdown format
    local normalized_formats=()
    for fmt in "${formats[@]}"; do
        if [[ "$fmt" == "md" ]]; then
            normalized_formats+=("markdown")
        else
            normalized_formats+=("$fmt")
        fi
    done
    formats=("${normalized_formats[@]}")

    print_info "Version table configuration:"
    print_info "  Formats: ${formats[*]}"
    print_info "  Output folder: $output_folder"
    print_info "  Base filename: $base_filename"

    # Check if extract-db-objects.py exists
    if [[ ! -f "extract-db-objects.py" ]]; then
        print_error "extract-db-objects.py not found in current directory"
        return 1
    fi

    # Create output folder if it doesn't exist
    if [[ ! -d "$output_folder" ]]; then
        if ! mkdir -p "$output_folder"; then
            print_error "Failed to create output folder: $output_folder"
            return 1
        fi
        print_info "Created output folder: $output_folder"
    fi

    # Determine Python command
    local python_cmd
    if command -v python3 &> /dev/null; then
        python_cmd="python3"
    elif command -v python &> /dev/null; then
        python_cmd="python"
    else
        print_error "Python not found. Please install Python 3.6+"
        return 1
    fi

    local generated_files=()

    # Generate each requested format
    for fmt in "${formats[@]}"; do
        # Determine extension
        local extension="$fmt"
        if [[ "$fmt" == "markdown" ]]; then
            extension="md"
        fi

        local output_file="$output_folder/$base_filename.$extension"

        print_info "Generating ${fmt^^} format: $output_file"

        local output
        if ! output=$($python_cmd "extract-db-objects.py" --format "$fmt" --output "$output_file" 2>&1); then
            print_error "Failed to generate $fmt: $output"
            return 1
        fi

        if [[ -f "$output_file" ]]; then
            print_success "Successfully generated $output_file"
            generated_files+=("$output_file")
        else
            print_error "$output_file was not created"
            return 1
        fi
    done

    if [[ ${#generated_files[@]} -gt 0 ]]; then
        print_success "Version table preparation completed successfully"
        print_info "Generated files: ${generated_files[*]}"
    else
        print_warning "No files were generated"
    fi

    return 0
}

# Execute SQL
exec_sql() {
    local sql_file="$1"
    local sql_command="$2"

    set_current_database "$DBDESTDB"

    if [[ -n "$sql_file" ]]; then
        print_info "Executing SQL file: $sql_file"
        $DBPSQLFILE -f "$sql_file"
    elif [[ -n "$sql_command" ]]; then
        print_info "Executing SQL command"
        $DBPSQLFILE -c "$sql_command"
    else
        print_info "Opening interactive psql session against $DBDESTDB ..."
        $DBPSQLFILE
    fi
}

# Global variables for test result passing (bash convention)
_TEST_RESULT_PASSED=true
_TEST_RESULT_PASS_COUNT=0
_TEST_RESULT_FAIL_COUNT=0
_TEST_RESULT_ERROR=false

# Read test manifest from suite directory
read_test_manifest() {
    local suite_dir="$1"
    local folder_name
    folder_name=$(basename "$suite_dir")

    # Default name: humanize folder name (strip test_ prefix, title case words)
    local display_name="$folder_name"
    if [[ "$display_name" == test_* ]]; then
        display_name="${display_name#test_}"
    fi
    # Title case: replace underscores with spaces, capitalize each word
    display_name=$(echo "$display_name" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1')

    _MANIFEST_NAME="$display_name"
    _MANIFEST_DESCRIPTION=""
    _MANIFEST_ALWAYS_CLEANUP=true
    _MANIFEST_ISOLATION="none"
    _MANIFEST_SETUP=()

    local manifest_file="$suite_dir/test.json"
    if [[ -f "$manifest_file" ]]; then
        # Use python3 one-liner to parse JSON (python already required by project)
        local json_data
        if json_data=$(python3 -c "
import json, sys
with open('$manifest_file') as f:
    d = json.load(f)
print(d.get('name', ''))
print(d.get('description', ''))
print(d.get('always_cleanup', True))
iso = d.get('isolation', 'none')
if iso not in ('none', 'transaction', 'database'):
    print('WARNING_UNKNOWN_ISOLATION:' + iso, file=sys.stderr)
    iso = 'none'
print(iso)
setup = d.get('setup', [])
if isinstance(setup, list):
    print('|'.join(setup))
else:
    print('')
" 2>/dev/null); then
            local name desc cleanup isolation setup_str
            name=$(echo "$json_data" | sed -n '1p')
            desc=$(echo "$json_data" | sed -n '2p')
            cleanup=$(echo "$json_data" | sed -n '3p')
            isolation=$(echo "$json_data" | sed -n '4p')
            setup_str=$(echo "$json_data" | sed -n '5p')
            [[ -n "$name" ]] && _MANIFEST_NAME="$name"
            [[ -n "$desc" ]] && _MANIFEST_DESCRIPTION="$desc"
            if [[ "$cleanup" == "False" || "$cleanup" == "false" ]]; then
                _MANIFEST_ALWAYS_CLEANUP=false
            fi
            [[ -n "$isolation" ]] && _MANIFEST_ISOLATION="$isolation"
            if [[ -n "$setup_str" ]]; then
                IFS='|' read -ra _MANIFEST_SETUP <<< "$setup_str"
            fi
        else
            print_warning "Failed to read $manifest_file"
        fi
    fi
}

# Run a single SQL test file via psql, sets global _TEST_RESULT_* variables
invoke_test_sql_file() {
    local file_path="$1"

    _TEST_RESULT_PASSED=true
    _TEST_RESULT_PASS_COUNT=0
    _TEST_RESULT_FAIL_COUNT=0
    _TEST_RESULT_ERROR=false

    local output exit_code
    set +e
    output=$($DBPSQLFILE -f "$file_path" 2>&1)
    exit_code=$?
    set -e

    # psql nonzero exit code = automatic FAIL
    if [[ $exit_code -ne 0 ]]; then
        _TEST_RESULT_ERROR=true
        _TEST_RESULT_PASSED=false
    fi

    # Count PASS/FAIL occurrences
    _TEST_RESULT_PASS_COUNT=$(echo "$output" | grep -c "PASS" || true)
    _TEST_RESULT_FAIL_COUNT=$(echo "$output" | grep -c "FAIL" || true)

    if [[ $_TEST_RESULT_FAIL_COUNT -gt 0 ]] || [[ "$_TEST_RESULT_ERROR" == true ]]; then
        _TEST_RESULT_PASSED=false
    fi

    # Colorize and print output
    if [[ "$TEST_VERBOSE" == true ]]; then
        while IFS= read -r line; do
            if [[ "$line" == *"PASS"* ]]; then
                echo -e "  ${GREEN}${line}${NC}"
            elif [[ "$line" == *"FAIL"* ]]; then
                echo -e "  ${RED}${line}${NC}"
            else
                echo "  $line"
            fi
        done <<< "$output"
    elif [[ "$_TEST_RESULT_PASSED" == false ]]; then
        # Silent mode: only print FAIL lines and error context
        while IFS= read -r line; do
            if [[ "$line" == *"FAIL"* ]]; then
                echo -e "  ${RED}${line}${NC}"
            elif [[ "$line" == *"ERROR"* ]] || [[ "$line" == *"error"* ]]; then
                echo -e "  ${RED}${line}${NC}"
            fi
        done <<< "$output"
    fi
}

# Run a suite in transaction isolation mode
# Expects: _TXN_MAIN_FILES=() _TXN_CLEANUP_FILES=() set by caller
invoke_suite_transaction() {
    local suite_dir="$1"
    local tests_dir="tests"

    _SUITE_PASSED=true
    _SUITE_PASS_COUNT=0
    _SUITE_FAIL_COUNT=0

    # Build wrapper SQL file
    local tmp_file="$suite_dir/_debee_txn_wrapper_$$.sql"
    {
        echo "\\set ON_ERROR_STOP on"
        echo "BEGIN;"

        # Shared setup files
        for setup_path in "${_MANIFEST_SETUP[@]}"; do
            local resolved="$tests_dir/$setup_path"
            if [[ -f "$resolved" ]]; then
                echo "\\echo '>>>DEBEE_FILE: $setup_path<<<'"
                echo "\\i '$resolved'"
            else
                print_warning "Shared setup file not found: $setup_path"
            fi
        done

        # Main files
        for f in "${_TXN_MAIN_FILES[@]}"; do
            [[ -z "$f" ]] && continue
            local fname
            fname=$(basename "$f")
            echo "\\echo '>>>DEBEE_FILE: $fname<<<'"
            echo "\\i '$f'"
        done

        echo "ROLLBACK;"
    } > "$tmp_file"

    # Run via psql
    local output exit_code
    set +e
    output=$($DBPSQLFILE -f "$tmp_file" 2>&1)
    exit_code=$?
    set -e

    # Remove temp file immediately
    rm -f "$tmp_file"

    local has_error=false
    if [[ $exit_code -ne 0 ]]; then
        has_error=true
    fi

    # Parse output by >>>DEBEE_FILE: ...<<< markers
    local current_file="(preamble)"
    declare -A file_outputs
    declare -a file_order=()

    while IFS= read -r line; do
        if [[ "$line" =~ ^\>\>\>DEBEE_FILE:\ (.+)\<\<\<$ ]]; then
            current_file="${BASH_REMATCH[1]}"
            if [[ -z "${file_outputs[$current_file]+x}" ]]; then
                file_outputs["$current_file"]=""
                file_order+=("$current_file")
            fi
        else
            if [[ -z "${file_outputs[$current_file]+x}" ]]; then
                file_outputs["$current_file"]=""
                file_order+=("$current_file")
            fi
            file_outputs["$current_file"]+="$line"$'\n'
        fi
    done <<< "$output"

    # Print and count per section
    for section_name in "${file_order[@]}"; do
        local section_pass section_fail
        section_pass=$(echo "${file_outputs[$section_name]}" | grep -c "PASS" || true)
        section_fail=$(echo "${file_outputs[$section_name]}" | grep -c "FAIL" || true)
        _SUITE_PASS_COUNT=$((_SUITE_PASS_COUNT + section_pass))
        _SUITE_FAIL_COUNT=$((_SUITE_FAIL_COUNT + section_fail))

        local section_errors
        section_errors=$(echo "${file_outputs[$section_name]}" | grep -c "ERROR" || true)

        if [[ "$TEST_VERBOSE" == true ]]; then
            if [[ "$section_name" != "(preamble)" ]]; then
                echo ""
                print_info "  -- $section_name --"
            fi

            while IFS= read -r line; do
                if [[ "$line" == *"PASS"* ]]; then
                    echo -e "  ${GREEN}${line}${NC}"
                elif [[ "$line" == *"FAIL"* ]]; then
                    echo -e "  ${RED}${line}${NC}"
                else
                    echo "  $line"
                fi
            done <<< "${file_outputs[$section_name]}"
        elif [[ $section_fail -gt 0 ]] || [[ $section_errors -gt 0 ]]; then
            if [[ "$section_name" != "(preamble)" ]]; then
                echo ""
                print_info "  -- $section_name --"
            fi

            while IFS= read -r line; do
                if [[ "$line" == *"FAIL"* ]]; then
                    echo -e "  ${RED}${line}${NC}"
                elif [[ "$line" == *"ERROR"* ]] || [[ "$line" == *"error"* ]]; then
                    echo -e "  ${RED}${line}${NC}"
                fi
            done <<< "${file_outputs[$section_name]}"
        fi
    done

    # Run cleanup files individually after rollback
    if [[ ${#_TXN_CLEANUP_FILES[@]} -gt 0 ]] && { [[ "$_MANIFEST_ALWAYS_CLEANUP" == true ]] || [[ "$has_error" == false ]]; }; then
        for f in "${_TXN_CLEANUP_FILES[@]}"; do
            [[ -z "$f" ]] && continue
            if [[ "$TEST_VERBOSE" == true ]]; then
                echo ""
                print_info "  -- $(basename "$f") (cleanup) --"
            fi
            invoke_test_sql_file "$f"
            if [[ "$_TEST_RESULT_PASSED" == false ]] && [[ "$TEST_VERBOSE" == false ]]; then
                echo ""
                print_info "  -- $(basename "$f") (cleanup) --"
            fi
            if [[ "$_TEST_RESULT_PASSED" == false ]]; then
                print_warning "Cleanup file $(basename "$f") had issues (non-fatal)"
            fi
        done
    fi

    if [[ $_SUITE_FAIL_COUNT -eq 0 ]] && [[ "$has_error" == false ]]; then
        _SUITE_PASSED=true
    else
        _SUITE_PASSED=false
    fi
}

# Run a flat test_*.sql file
invoke_flat_test() {
    local test_file="$1"
    if [[ "$TEST_VERBOSE" == true ]]; then
        echo ""
        print_info "--- $(basename "$test_file") ---"
    fi
    invoke_test_sql_file "$test_file"
    if [[ "$TEST_VERBOSE" == false ]] && [[ "$_TEST_RESULT_PASSED" == false ]]; then
        echo ""
        echo -e "--- $(basename "$test_file") --- ${RED}FAILED${NC}"
    fi
}

# Run a folder-based test suite
invoke_suite_test() {
    local suite_dir="$1"

    read_test_manifest "$suite_dir"

    local suite_pass_count=0
    local suite_fail_count=0
    local suite_passed=true
    local suite_header_printed=false

    if [[ "$TEST_VERBOSE" == true ]]; then
        echo ""
        print_info "=== Suite: $_MANIFEST_NAME ==="
        if [[ -n "$_MANIFEST_DESCRIPTION" ]]; then
            print_info "$_MANIFEST_DESCRIPTION"
        fi
        suite_header_printed=true
    fi

    # Discover SQL files matching NNN_*.sql
    local main_files=()
    local cleanup_files=()

    for f in "$suite_dir"/*; do
        [[ ! -f "$f" ]] && continue
        local fname
        fname=$(basename "$f")

        if [[ "$fname" =~ ^[0-9]{3}_.*\.sql$ ]]; then
            local prefix
            prefix=$((10#${fname:0:3}))
            if [[ $prefix -ge 900 ]] && [[ $prefix -le 999 ]]; then
                cleanup_files+=("$f")
            else
                main_files+=("$f")
            fi
        elif [[ "$fname" != "test.json" ]]; then
            print_warning "Skipping non-matching file in suite: $fname"
        fi
    done

    # Sort arrays
    IFS=$'\n' main_files=($(sort <<<"${main_files[*]}")); unset IFS
    IFS=$'\n' cleanup_files=($(sort <<<"${cleanup_files[*]}")); unset IFS

    # Branch on isolation mode
    if [[ "$_MANIFEST_ISOLATION" == "transaction" ]]; then
        _TXN_MAIN_FILES=("${main_files[@]}")
        _TXN_CLEANUP_FILES=("${cleanup_files[@]}")
        invoke_suite_transaction "$suite_dir"
        suite_passed=$_SUITE_PASSED
        suite_pass_count=$_SUITE_PASS_COUNT
        suite_fail_count=$_SUITE_FAIL_COUNT
    elif [[ "$_MANIFEST_ISOLATION" == "database" ]]; then
        # Recreate + restore database before suite
        print_info "  [database isolation] Recreating database..."
        recreate_database
        if [[ -n "$DBBACKUPFILE" ]]; then
            print_info "  [database isolation] Restoring database..."
            restore_database
        fi
        set_current_database "$DBDESTDB"

        # Run shared setup files individually
        local tests_dir="tests"
        for setup_path in "${_MANIFEST_SETUP[@]}"; do
            local resolved="$tests_dir/$setup_path"
            if [[ -f "$resolved" ]]; then
                if [[ "$TEST_VERBOSE" == true ]]; then
                    echo ""
                    print_info "  -- $setup_path (shared setup) --"
                fi
                invoke_test_sql_file "$resolved"
            else
                print_warning "Shared setup file not found: $setup_path"
            fi
        done

        # Run main files individually
        local main_failed=false
        for f in "${main_files[@]}"; do
            [[ -z "$f" ]] && continue
            if [[ "$TEST_VERBOSE" == true ]]; then
                echo ""
                print_info "  -- $(basename "$f") --"
            fi
            invoke_test_sql_file "$f"
            suite_pass_count=$((suite_pass_count + _TEST_RESULT_PASS_COUNT))
            suite_fail_count=$((suite_fail_count + _TEST_RESULT_FAIL_COUNT))
            if [[ "$_TEST_RESULT_PASSED" == false ]]; then
                if [[ "$suite_header_printed" == false ]]; then
                    echo ""
                    print_info "=== Suite: $_MANIFEST_NAME ==="
                    suite_header_printed=true
                fi
                if [[ "$TEST_VERBOSE" == false ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") --"
                fi
                main_failed=true
                break
            fi
        done

        if [[ ${#cleanup_files[@]} -gt 0 ]] && { [[ "$_MANIFEST_ALWAYS_CLEANUP" == true ]] || [[ "$main_failed" == false ]]; }; then
            for f in "${cleanup_files[@]}"; do
                [[ -z "$f" ]] && continue
                if [[ "$TEST_VERBOSE" == true ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") (cleanup) --"
                fi
                invoke_test_sql_file "$f"
                if [[ "$_TEST_RESULT_PASSED" == false ]] && [[ "$TEST_VERBOSE" == false ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") (cleanup) --"
                fi
                if [[ "$_TEST_RESULT_PASSED" == false ]]; then
                    print_warning "Cleanup file $(basename "$f") had issues (non-fatal)"
                fi
            done
        fi

        if [[ "$main_failed" == false ]] && [[ $suite_fail_count -eq 0 ]]; then
            suite_passed=true
        else
            suite_passed=false
        fi
    else
        # "none" — current behavior with shared setup
        local tests_dir="tests"
        for setup_path in "${_MANIFEST_SETUP[@]}"; do
            local resolved="$tests_dir/$setup_path"
            if [[ -f "$resolved" ]]; then
                if [[ "$TEST_VERBOSE" == true ]]; then
                    echo ""
                    print_info "  -- $setup_path (shared setup) --"
                fi
                invoke_test_sql_file "$resolved"
            else
                print_warning "Shared setup file not found: $setup_path"
            fi
        done

        # Run main phase (stop on first failure)
        local main_failed=false
        for f in "${main_files[@]}"; do
            [[ -z "$f" ]] && continue
            if [[ "$TEST_VERBOSE" == true ]]; then
                echo ""
                print_info "  -- $(basename "$f") --"
            fi
            invoke_test_sql_file "$f"
            suite_pass_count=$((suite_pass_count + _TEST_RESULT_PASS_COUNT))
            suite_fail_count=$((suite_fail_count + _TEST_RESULT_FAIL_COUNT))

            if [[ "$_TEST_RESULT_PASSED" == false ]]; then
                if [[ "$suite_header_printed" == false ]]; then
                    echo ""
                    print_info "=== Suite: $_MANIFEST_NAME ==="
                    suite_header_printed=true
                fi
                if [[ "$TEST_VERBOSE" == false ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") --"
                fi
                main_failed=true
                break
            fi
        done

        # Run cleanup phase
        if [[ ${#cleanup_files[@]} -gt 0 ]] && { [[ "$_MANIFEST_ALWAYS_CLEANUP" == true ]] || [[ "$main_failed" == false ]]; }; then
            for f in "${cleanup_files[@]}"; do
                [[ -z "$f" ]] && continue
                if [[ "$TEST_VERBOSE" == true ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") (cleanup) --"
                fi
                invoke_test_sql_file "$f"
                if [[ "$_TEST_RESULT_PASSED" == false ]] && [[ "$TEST_VERBOSE" == false ]]; then
                    echo ""
                    print_info "  -- $(basename "$f") (cleanup) --"
                fi
                if [[ "$_TEST_RESULT_PASSED" == false ]]; then
                    print_warning "Cleanup file $(basename "$f") had issues (non-fatal)"
                fi
            done
        fi

        if [[ "$main_failed" == false ]] && [[ $suite_fail_count -eq 0 ]]; then
            suite_passed=true
        else
            suite_passed=false
        fi
    fi

    if [[ "$suite_passed" == true ]]; then
        if [[ "$TEST_VERBOSE" == true ]]; then
            echo ""
            print_success "Suite $_MANIFEST_NAME: PASSED"
        fi
    else
        if [[ "$suite_header_printed" == false ]]; then
            echo ""
            print_info "=== Suite: $_MANIFEST_NAME ==="
        fi
        echo ""
        print_error "Suite $_MANIFEST_NAME: FAILED"
    fi

    # Set globals for caller
    _SUITE_PASSED=$suite_passed
    _SUITE_PASS_COUNT=$suite_pass_count
    _SUITE_FAIL_COUNT=$suite_fail_count
}

# Run tests
run_tests() {
    local filter="$1"
    local tests_dir="tests"

    if [[ ! -d "$tests_dir" ]]; then
        print_warning "Tests directory not found: $tests_dir"
        return 1
    fi

    set_current_database "$DBDESTDB"

    # Discover test items: flat test_*.sql files + test_*/ directories
    local item_types=()
    local item_paths=()

    for entry in "$tests_dir"/test_*; do
        [[ ! -e "$entry" ]] && continue
        local name
        name=$(basename "$entry")

        if [[ -d "$entry" ]]; then
            # Apply filter
            if [[ "$filter" != "all" ]] && [[ "$name" != *"$filter"* ]]; then
                continue
            fi
            item_types+=("suite")
            item_paths+=("$entry")
        elif [[ -f "$entry" ]] && [[ "$name" == *.sql ]]; then
            # Apply filter
            if [[ "$filter" != "all" ]] && [[ "$name" != *"$filter"* ]]; then
                continue
            fi
            item_types+=("file")
            item_paths+=("$entry")
        fi
    done

    # Apply global ordering from tests/tests.json
    local tests_json="$tests_dir/tests.json"
    if [[ -f "$tests_json" ]]; then
        local order_data
        if order_data=$(python3 -c "
import json, sys
with open('$tests_json') as f:
    d = json.load(f)
for name in d.get('order', []):
    print(name)
" 2>/dev/null); then
            if [[ -n "$order_data" ]]; then
                local ordered_types=()
                local ordered_paths=()
                local used=()

                # Initialize used array
                for i in "${!item_types[@]}"; do
                    used+=("false")
                done

                while IFS= read -r order_name; do
                    for i in "${!item_paths[@]}"; do
                        local iname
                        iname=$(basename "${item_paths[$i]}")
                        if [[ "$iname" == "$order_name" ]] && [[ "${used[$i]}" == "false" ]]; then
                            ordered_types+=("${item_types[$i]}")
                            ordered_paths+=("${item_paths[$i]}")
                            used[$i]="true"
                            break
                        fi
                    done
                done <<< "$order_data"

                # Add remaining items
                for i in "${!item_types[@]}"; do
                    if [[ "${used[$i]}" == "false" ]]; then
                        ordered_types+=("${item_types[$i]}")
                        ordered_paths+=("${item_paths[$i]}")
                    fi
                done

                item_types=("${ordered_types[@]}")
                item_paths=("${ordered_paths[@]}")
            fi
        else
            print_warning "Failed to read $tests_json"
        fi
    fi

    if [[ ${#item_types[@]} -eq 0 ]]; then
        print_warning "No test items found matching filter: $filter"
        return 1
    fi

    local file_count=0
    local suite_count=0
    for t in "${item_types[@]}"; do
        [[ "$t" == "file" ]] && file_count=$((file_count + 1))
        [[ "$t" == "suite" ]] && suite_count=$((suite_count + 1))
    done

    if [[ "$TEST_VERBOSE" == true ]]; then
        print_info "Running ${#item_types[@]} test item(s) ($file_count file(s), $suite_count suite(s))..."
    fi

    # Collect results
    local all_pass_counts=()
    local all_fail_counts=()
    local all_passed=()
    local all_is_suite=()
    local all_errors=()

    for i in "${!item_types[@]}"; do
        if [[ "${item_types[$i]}" == "file" ]]; then
            invoke_flat_test "${item_paths[$i]}"
            all_pass_counts+=("$_TEST_RESULT_PASS_COUNT")
            all_fail_counts+=("$_TEST_RESULT_FAIL_COUNT")
            all_passed+=("$_TEST_RESULT_PASSED")
            all_is_suite+=(false)
            all_errors+=("$_TEST_RESULT_ERROR")
        else
            invoke_suite_test "${item_paths[$i]}"
            all_pass_counts+=("$_SUITE_PASS_COUNT")
            all_fail_counts+=("$_SUITE_FAIL_COUNT")
            all_passed+=("$_SUITE_PASSED")
            all_is_suite+=(true)
            all_errors+=(false)
        fi
    done

    # Summary
    local total_pass=0 total_fail=0 error_only=0
    local suite_passed_count=0 suite_failed_count=0
    local file_passed_count=0 file_failed_count=0

    for i in "${!all_passed[@]}"; do
        total_pass=$((total_pass + all_pass_counts[$i]))
        total_fail=$((total_fail + all_fail_counts[$i]))

        if [[ "${all_errors[$i]}" == true ]] && [[ ${all_fail_counts[$i]} -eq 0 ]]; then
            error_only=$((error_only + 1))
        fi

        if [[ "${all_is_suite[$i]}" == true ]]; then
            if [[ "${all_passed[$i]}" == true ]]; then
                suite_passed_count=$((suite_passed_count + 1))
            else
                suite_failed_count=$((suite_failed_count + 1))
            fi
        else
            if [[ "${all_passed[$i]}" == true ]]; then
                file_passed_count=$((file_passed_count + 1))
            else
                file_failed_count=$((file_failed_count + 1))
            fi
        fi
    done

    echo ""
    print_info "=== Test Summary ==="
    print_success "PASSED: $total_pass"
    if [[ $total_fail -gt 0 ]] || [[ $error_only -gt 0 ]]; then
        local fail_msg="FAILED: $total_fail"
        if [[ $error_only -gt 0 ]]; then
            fail_msg="$fail_msg (+$error_only error(s))"
        fi
        print_error "$fail_msg"
    else
        print_info "FAILED: $total_fail"
    fi
    print_info "Total:  $((total_pass + total_fail))"
    if [[ $suite_count -gt 0 ]]; then
        print_info "Suites: $suite_passed_count passed, $suite_failed_count failed"
    fi
    if [[ $file_count -gt 0 ]]; then
        print_info "Files:  $file_passed_count passed, $file_failed_count failed"
    fi

    # Return failure if any test failed
    for p in "${all_passed[@]}"; do
        if [[ "$p" == false ]]; then
            return 1
        fi
    done
    return 0
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

PostgreSQL Migration Orchestrator - Bash Version

Options:
    -e, --environment ENV       Environment name for configuration
    -o, --operations OPS        Comma-separated operations to perform
                               (recreateDatabase, restoreDatabase, updateDatabase,
                                preUpdateScripts, postUpdateScripts, prepareVersionTable,
                                execSql, runTests, fullService)
                               Default: fullService
    -s, --start-number NUM     Starting migration file number (default: -1 for all)
    -n, --end-number NUM       Ending migration file number (default: -1 for all)
    --sql-file FILE            SQL file to execute (for execSql operation)
    --sql "QUERY"              SQL command to execute inline (for execSql operation)
    --test-filter PATTERN      Filter test files by pattern (for runTests operation, default: all)
    --test-verbose             Show all test output including PASS lines (default: silent, only failures shown)
    -q, --silent               Suppress orchestration messages (env loading, operation banners,
                               final success). Warnings, errors, and psql output remain visible.
    -y, --yes                  Skip production confirmation prompt (required for automation
                               when DBPRODENVIRONMENT=true is set in the env file)
    -V, --version              Print version and exit
    -h, --help                 Show this help message
    --llm                      Print full CLI reference for LLM/AI assistants and exit

Examples:
    $0 -e prod -o fullService
    $0 -e dev -o restoreDatabase,updateDatabase
    $0 -o updateDatabase -s 10 -n 20
    $0 -o execSql --sql "SELECT 1;"
    $0 -o execSql --sql-file script.sql
    $0 -o runTests
    $0 -o runTests --test-filter connection

Environment files:
    debee.ENV.env              Environment-specific configuration
    .debee.ENV.env             Local overrides (git-ignored)
    debee.env                  Default configuration (when no environment specified)
    .debee.env                 Local default overrides

EOF
}

# Show full LLM/AI reference document
show_llm() {
    echo "debee v$DEBEE_VERSION - PostgreSQL Migration Orchestrator"
    cat << 'DEBEE_LLM_EOF'

Cross-platform database migration runner for PostgreSQL. Three interchangeable implementations:
  debee.ps1 (PowerShell, Windows-primary) | debee.sh (Bash, Linux/macOS) | debee.py (Python, cross-platform)

CONCEPT

debee is a pure orchestration layer: all database logic lives in external .sql files. It reads
connection + behavior settings from .env files, then runs a sequence of operations (recreate /
restore / migrate / test / document) against a target PostgreSQL database using the system `psql`
and `pg_restore` binaries. It performs no DB logic of its own beyond invoking those SQL files.

INVOCATION

  PowerShell:  .\debee.ps1 -Operations <op>[,<op>...] [options]
  Bash:        ./debee.sh   -o <op>[,<op>...] [options]
  Python:      python debee.py -o <op>[,<op>...] [options]

Run from the directory that holds your .env file, migration files (NNN_*.sql), and (as needed) the
recreate script, backup file, tests/ folder, and extract-db-objects.py. Migration files and tests
are discovered relative to the current working directory.

OPERATIONS  (comma-separated; default: fullService)

  recreateDatabase     Drop and recreate the target DB by running the SQL script in DBRECREATESCRIPT,
                       connected to DBCONNECTDB. Destructive.
  restoreDatabase      Restore the target DB from DBBACKUPFILE using pg_restore (or psql for plain
                       SQL). Format set by DBBACKUPTYPE (custom/plain/dir/tar). Parallel jobs via
                       DBRESTOREJOBCOUNT. Optionally creates the DB first when DBCREATEONRESTORE=true.
  updateDatabase       Apply numbered migration files matching ^NNN_*.sql in the current directory,
                       ascending, within the [start..end] range. Empty files are skipped.
  preUpdateScripts     Run the semicolon-separated SQL files in DBPREUPDATESCRIPTS (before update).
  postUpdateScripts    Run the semicolon-separated SQL files in DBPOSTUPDATESCRIPTS (after update).
  prepareVersionTable  Extract DB objects via extract-db-objects.py and emit documentation in the
                       formats from DBVERSIONTABLEFORMATS (json;md;csv;html) to DBVERSIONTABLEOUTPUTFOLDER.
  execSql              Run ad-hoc SQL: inline via --sql / -Sql, or a file via --sql-file / -SqlFile.
                       With neither, opens an interactive psql session against the target DB.
  runTests             Run SQL test files / suites from the tests/ folder. Global ordering from
                       tests/tests.json. Filter with --test-filter; show PASS lines with --test-verbose.
  fullService          recreateDatabase + restoreDatabase + preUpdateScripts + updateDatabase +
                       postUpdateScripts, in sequence. Destructive - recreates and restores the DB.

MIGRATION FILE NAMING

  Pattern: NNN_description.sql
    NNN          exactly 3 digits (001, 060, 999) - the ordering/selection key
    _            underscore separator
    description  any text
    .sql         required extension
  Files not matching ^\d{3}_.*\.sql$ are ignored. The range is inclusive; -1 means unbounded on that
  end (start=-1, end=-1 -> all files). Start must not exceed a non-(-1) end.

OPTIONS  (PowerShell / Bash + Python)

  -Operations        / -o, --operations      Comma-separated operations (default fullService)
  -Environment       / -e, --environment      Load debee.<name>.env instead of debee.env
  -UpdateStartNumber / -s, --start-number     First migration number (default: env DBUPDATESTARTNUMBER, else all)
  -UpdateEndNumber   / -n, --end-number       Last migration number  (default: env DBUPDATEENDNUMBER, else all)
  -SqlFile           / --sql-file             SQL file to run (execSql)
  -Sql               / --sql                  Inline SQL to run (execSql)
  -TestFilter        / --test-filter          Filter test files by pattern (runTests; default all)
  -TestVerbose       / --test-verbose         Show all test output including PASS lines
  -Silent, -q        / -q, --silent           Suppress orchestration messages; errors + psql output remain
  -Yes, -y           / -y, --yes              Skip production confirmation (needed for automation when DBPRODENVIRONMENT=true)
  -Version, -V       / -V, --version          Print version and exit
  -Help, -h          / -h, --help             Show short help
  -Llm               / --llm                  Print this reference document

ENVIRONMENT FILES  (loaded from the current directory)

  With -Environment/-e NAME:  debee.<NAME>.env   then  .debee.<NAME>.env   (local overrides, gitignored)
  Without an environment:     debee.env          then  .debee.env
  The base file must exist; the .local file is optional and layered on top (later wins).

ENVIRONMENT VARIABLES

  Connection (standard libpq):
    PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE
  Core:
    DBDESTDB              Target database name (required by most operations)
    DBCONNECTDB           Maintenance/connect DB used while dropping/creating (e.g. postgres)
    DBRECREATESCRIPT      SQL file run by recreateDatabase
  Restore:
    DBBACKUPFILE          Path to the backup to restore
    DBBACKUPTYPE          Backup format: custom (default) / plain / dir / tar
    DBRESTOREJOBCOUNT     Parallel pg_restore jobs (-j)
    DBCREATEONRESTORE     true -> create the DB before restoring
  Migrations:
    DBUPDATESTARTNUMBER   Default start number when -s/-UpdateStartNumber not given
    DBUPDATEENDNUMBER     Default end number when -n/-UpdateEndNumber not given
    DBPREUPDATESCRIPTS    Semicolon-separated SQL files for preUpdateScripts
    DBPOSTUPDATESCRIPTS   Semicolon-separated SQL files for postUpdateScripts
  Version table:
    DBVERSIONTABLEFORMATS       Semicolon list: json;md;csv;html (default json;md)
    DBVERSIONTABLEOUTPUTFOLDER  Output directory (default .)
    DBVERSIONTABLEFILENAME      Base output filename (default db-objects)
  Tooling / safety:
    DBPSQLFILE            psql binary/path (default psql)
    DBPGRESTOREFILE       pg_restore binary/path (default pg_restore)
    DBPRODENVIRONMENT     true -> require typed 'yes' confirmation before running (bypass with -Yes/-y)

PRODUCTION CONFIRMATION

  When DBPRODENVIRONMENT=true, debee prints the host/user/target-DB and operation list and requires
  the user to type 'yes' before proceeding. Pass -Yes/-y to skip it in automated/CI runs.

EXAMPLES

  .\debee.ps1 -Operations fullService -Environment prod
  ./debee.sh      -e dev -o restoreDatabase,updateDatabase
  python debee.py -o updateDatabase -s 10 -n 20
  .\debee.ps1 -Operations execSql -Sql "SELECT version();" -Silent
  ./debee.sh      -o execSql --sql-file script.sql
  python debee.py -o runTests --test-filter connection
DEBEE_LLM_EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -o|--operations)
            IFS=',' read -ra OPERATIONS <<< "$2"
            shift 2
            ;;
        -s|--start-number)
            UPDATE_START_NUMBER="$2"
            shift 2
            ;;
        -n|--end-number)
            UPDATE_END_NUMBER="$2"
            shift 2
            ;;
        --sql-file)
            SQL_FILE="$2"
            shift 2
            ;;
        --sql)
            SQL_COMMAND="$2"
            shift 2
            ;;
        --test-filter)
            TEST_FILTER="$2"
            shift 2
            ;;
        --test-verbose)
            TEST_VERBOSE=true
            shift
            ;;
        -q|--silent)
            SILENT=true
            shift
            ;;
        -y|--yes)
            ASSUME_YES=true
            shift
            ;;
        -V|--version)
            echo "debee.sh $DEBEE_VERSION"
            exit 0
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        --llm)
            show_llm
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution

# Define environment file paths
if [[ -n "$ENVIRONMENT" ]]; then
    ENV_FILE="debee.$ENVIRONMENT.env"
    LOCAL_ENV_FILE=".debee.$ENVIRONMENT.env"
else
    ENV_FILE="debee.env"
    LOCAL_ENV_FILE=".debee.env"
fi

# Check if environment file exists
if [[ ! -f "$ENV_FILE" ]]; then
    print_error "Could not find $ENV_FILE"
    exit 1
fi

# Load environment files
prepare_environment "$ENV_FILE"

# Load local environment file if it exists
if [[ -f "$LOCAL_ENV_FILE" ]]; then
    prepare_environment "$LOCAL_ENV_FILE"
fi

# Bash arithmetic reads a leading zero as octal ("051" -> 41, "008" is an error), so normalize
# CLI and env range values to decimal the way file prefixes are parsed. -1 (all) stays as is.
for __range_var in UPDATE_START_NUMBER UPDATE_END_NUMBER DBUPDATESTARTNUMBER DBUPDATEENDNUMBER; do
    if [[ ${!__range_var} =~ ^[0-9]+$ ]]; then
        printf -v "$__range_var" '%d' "$((10#${!__range_var}))"
    fi
done

# Resolve migration range: CLI flags win; otherwise fall back to env vars loaded above.
if [[ $UPDATE_START_NUMBER -eq -1 ]] && [[ -n "$DBUPDATESTARTNUMBER" ]] && [[ $DBUPDATESTARTNUMBER -gt 0 ]]; then
    UPDATE_START_NUMBER=$DBUPDATESTARTNUMBER
fi
if [[ $UPDATE_END_NUMBER -eq -1 ]] && [[ -n "$DBUPDATEENDNUMBER" ]] && [[ $DBUPDATEENDNUMBER -ge 1 ]]; then
    UPDATE_END_NUMBER=$DBUPDATEENDNUMBER
fi


# Set default tool paths if not defined
: ${DBPSQLFILE:=psql}
: ${DBPGRESTOREFILE:=pg_restore}

# Production confirmation
confirm_production() {
    local prod_flag="${DBPRODENVIRONMENT,,}"  # lowercase
    if [[ "$prod_flag" != "true" && "$prod_flag" != "1" ]]; then
        return 0
    fi
    if [[ "$ASSUME_YES" == true ]]; then
        return 0
    fi

    local ops_csv
    ops_csv=$(IFS=,; echo "${OPERATIONS[*]}")

    # Always print, even in silent mode — confirmation must be visible
    echo "" >&2
    echo -e "${RED}==============================================${NC}" >&2
    echo -e "${RED}  PRODUCTION ENVIRONMENT - CONFIRMATION REQUIRED${NC}" >&2
    echo -e "${RED}==============================================${NC}" >&2
    echo "" >&2
    [[ -n "$ENVIRONMENT" ]] && echo "  Environment:  $ENVIRONMENT" >&2
    echo "  Host:         ${PGHOST:-localhost}:${PGPORT:-5432}" >&2
    echo "  User:         ${PGUSER:-<unset>}" >&2
    echo "  Target DB:    ${DBDESTDB:-<unset>}" >&2
    echo "  Operations:   $ops_csv" >&2
    if [[ " ${OPERATIONS[*]} " == *" execSql "* ]]; then
        if [[ -n "$SQL_FILE" ]]; then
            echo "  SQL file:     $SQL_FILE" >&2
        elif [[ -n "$SQL_COMMAND" ]]; then
            echo "  SQL command:  $SQL_COMMAND" >&2
        else
            echo "  SQL:          (interactive psql session)" >&2
        fi
    fi
    if [[ " ${OPERATIONS[*]} " == *" updateDatabase "* ]]; then
        local range_text
        if [[ $UPDATE_START_NUMBER -eq -1 && $UPDATE_END_NUMBER -eq -1 ]]; then
            range_text="all"
        elif [[ $UPDATE_END_NUMBER -eq -1 ]]; then
            range_text="${UPDATE_START_NUMBER} onwards"
        elif [[ $UPDATE_START_NUMBER -eq -1 ]]; then
            range_text="up to ${UPDATE_END_NUMBER}"
        else
            range_text="${UPDATE_START_NUMBER} -> ${UPDATE_END_NUMBER}"
        fi
        echo "  Migration range: ${range_text}" >&2
    fi
    echo "" >&2

    local response=""
    read -r -p '  Type "yes" to proceed (anything else aborts): ' response || true
    echo "" >&2

    local response_lower="${response,,}"
    if [[ "$response_lower" != "yes" ]]; then
        print_error "Production run aborted by user."
        exit 1
    fi
}

confirm_production

# Process operations
for operation in "${OPERATIONS[@]}"; do
    print_info "Processing: $operation"

    case "$operation" in
        "recreateDatabase")
            print_info "Performing recreate operation..."
            recreate_database
            ;;
        "restoreDatabase")
            print_info "Performing restore operation..."
            restore_database
            ;;
        "updateDatabase")
            print_info "Performing update operation..."
            update_database
            ;;
        "preUpdateScripts")
            print_info "Performing pre-update operation..."
            run_pre_update_scripts
            ;;
        "postUpdateScripts")
            print_info "Performing post-update operation..."
            run_post_update_scripts
            ;;
        "prepareVersionTable")
            print_info "Performing prepare version table operation..."
            prepare_version_table
            ;;
        "execSql")
            print_info "Performing exec SQL operation..."
            exec_sql "$SQL_FILE" "$SQL_COMMAND"
            ;;
        "runTests")
            print_info "Performing run tests operation..."
            run_tests "$TEST_FILTER"
            ;;
        "fullService")
            print_info "Performing full service operation..."
            recreate_database
            restore_database
            run_pre_update_scripts
            update_database
            run_post_update_scripts
            ;;
        *)
            print_error "Invalid operation specified: $operation"
            print_info "Valid operations: recreateDatabase, restoreDatabase, updateDatabase, preUpdateScripts, postUpdateScripts, prepareVersionTable, execSql, runTests, fullService"
            exit 1
            ;;
    esac
done

print_success "All operations completed successfully!"