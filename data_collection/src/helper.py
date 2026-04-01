import os

from datetime import datetime, timedelta

try:
    from ..config import OUTPUT_DIR
except ImportError:
    from config import OUTPUT_DIR


def _find_latest_file(filename: str, max_days_back: int = 7):
    """
    Search backwards from today to find the most recent file.
    """
    now = datetime.utcnow()

    for days_back in range(max_days_back + 1):
        check_day = now - timedelta(days=days_back)

        year = check_day.strftime("%Y")
        month = check_day.strftime("%m")
        day = check_day.strftime("%d")

        current_dir = os.path.join(OUTPUT_DIR, year, month, day)
        candidate = os.path.join(current_dir, filename)

        if os.path.exists(candidate):
            print(f"Found file: {candidate}")
            return candidate, current_dir

    print(f"File not found within {max_days_back} days: {filename}")
    return None

def _require_latest_file(filename: str, max_days_back: int = 7):
    latest = _find_latest_file(filename, max_days_back=max_days_back)
    if latest is None:
        raise FileNotFoundError(
            f"Could not find a recent file named {filename!r} under {OUTPUT_DIR}"
        )
    return latest

def get_day_directory() -> str:
    """
    Get (and create if does not exist) directory for output files.
    Follows: OUTPUT_DIR/year/month/day structure
    
    :return: Path to output directory
    :rtype: str
    """
    now = datetime.utcnow()

    year = now.strftime("%Y")
    month = now.strftime("%m")
    day = now.strftime("%d")

    day_dir = os.path.join(OUTPUT_DIR, year, month, day)
    os.makedirs(day_dir, exist_ok=True)

    return day_dir

def get_sl_files(name=None):
    # this file populates later than the sec_to_last file, so use this
    # file for consistency
    filename = f"{name}_sl_mapping.csv" if name else "sl_mapping.csv"
    file, day_dir = _require_latest_file(filename)

    return file, os.path.join(
        day_dir, 
        f"{name}_sec_to_last.csv" if name else "sec_to_last.csv"
    )

def get_time_bucket_file(base_output_dir: str, data_dir: str, type: str) -> str:
    now = datetime.utcnow()
    minute_bucket = (now.minute // 5) * 5
    bucket_time = now.replace(minute=minute_bucket, second=0, microsecond=0)

    year = bucket_time.strftime("%Y")
    month = bucket_time.strftime("%m")
    day = bucket_time.strftime("%d")
    hhmm = bucket_time.strftime("%H%M")

    dir_path = os.path.join(base_output_dir, year, month, day, data_dir if data_dir else 'data')
    os.makedirs(dir_path, exist_ok=True)

    return os.path.join(dir_path, f"{hhmm}_{type}.json")

def find_latest_sec_last(output_dir: str, filename: str):
    """
    Find the newest sec_last file by searching backwards by day.
    """

    now = datetime.utcnow()
    days_back = 0

    while True:
        check_day = now - timedelta(days=days_back)

        year = check_day.strftime("%Y")
        month = check_day.strftime("%m")
        day = check_day.strftime("%d")

        day_dir = os.path.join(output_dir, year, month, day)
        candidate = os.path.join(day_dir, filename)

        if os.path.exists(candidate):
            print(f"Found sec_last file: {candidate}")
            return candidate

        print(f"Not found: {candidate}")

        days_back += 1

        # Stop searching too far back
        if days_back > 7:
            return None
