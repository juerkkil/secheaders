import shutil
import sys
import textwrap

from .constants import WARN_COLOR, OK_COLOR, END_COLOR, COLUMN_WIDTH_R


def get_eval_output(warn, no_color):
    color_start = OK_COLOR
    color_end = END_COLOR
    eval_result = "OK"
    if warn:
        color_start = WARN_COLOR
        eval_result = "WARN"

    if no_color:
        color_start = ""
        color_end = ""

    return f"[ {color_start}{eval_result}{color_end} ]"


def output_text(target_url, headers, https, no_color=False, verbose=False) -> str:
    terminal_width = shutil.get_terminal_size().columns
    output_str = f"Scanning target {target_url} ...\n"

    # If the stdout is not going into terminal, disable colors
    no_color = no_color or not sys.stdout.isatty()
    for header, value in headers.items():
        truncated = False
        if not value['defined']:
            output = f"Header '{header}' is missing"
        else:
            output = f"{header}: {value['contents']}"
            if len(output) > terminal_width - COLUMN_WIDTH_R:
                truncated = True
                output = f"{output[0:(terminal_width - COLUMN_WIDTH_R - 3)]}..."

        eval_value = get_eval_output(value['warn'], no_color)

        if no_color:
            output_str += f"{output:<{terminal_width - COLUMN_WIDTH_R}}{eval_value:^{COLUMN_WIDTH_R}}\n"
        else:
            # This is a dirty hack required to align ANSI-colored str correctly
            output_str += f"{output:<{terminal_width - COLUMN_WIDTH_R}}{eval_value:^{COLUMN_WIDTH_R + 9}}\n"

        if truncated and verbose:
            output_str += f"Full header contents: {value['contents']}\n"
        for note in value['notes']:
            output_str += textwrap.fill(f" * {note}", terminal_width - COLUMN_WIDTH_R, subsequent_indent='   ')
            output_str += "\n"

    msg_map = {
        'supported': 'HTTPS supported',
        'certvalid': 'HTTPS valid certificate',
        'redirect': 'HTTP -> HTTPS automatic redirect',
    }
    if https:
        for key in https:
            output = f"{msg_map[key]}"
            eval_value = get_eval_output(not https[key], no_color)
            if no_color:
                output = f"{output:<{terminal_width - COLUMN_WIDTH_R}}{eval_value:^{COLUMN_WIDTH_R}}\n"
            else:
                # This is a dirty hack required to align ANSI-colored str correctly
                output = f"{output:<{terminal_width - COLUMN_WIDTH_R}}{eval_value:^{COLUMN_WIDTH_R + 9}}\n"

            output_str += output

    return output_str
