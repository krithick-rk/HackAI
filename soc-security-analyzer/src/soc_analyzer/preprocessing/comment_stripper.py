import os
from src.soc_analyzer.preprocessing.keyword_config import PRESERVED_KEYWORDS

def strip_comments(source_text: str, preserve_keywords: list[str] | None = None) -> str:
    """
    Strips single-line (//) and multi-line (/* */) comments from Verilog/SystemVerilog source text.
    Preserves comments containing security-relevant keywords (case-insensitive substring match).
    Maintains line numbers and column offsets by replacing stripped content with spaces/newlines.
    Does not inspect comments inside string literals or compiler directives.
    """
    if preserve_keywords is None:
        preserve_keywords = PRESERVED_KEYWORDS
        
    keywords = [kw.lower() for kw in preserve_keywords]
    
    n = len(source_text)
    i = 0
    output = []
    
    # State: 'normal', 'string', 'compiler_directive', 'line_comment', 'block_comment'
    state = 'normal'
    comment_buf = []
    
    while i < n:
        char = source_text[i]
        
        if state == 'normal':
            if char == '"':
                state = 'string'
                output.append(char)
                i += 1
            elif char == '`':
                state = 'compiler_directive'
                output.append(char)
                i += 1
            elif char == '/' and i + 1 < n and source_text[i+1] == '/':
                state = 'line_comment'
                comment_buf = []
                i += 2
            elif char == '/' and i + 1 < n and source_text[i+1] == '*':
                state = 'block_comment'
                comment_buf = []
                i += 2
            else:
                output.append(char)
                i += 1
                
        elif state == 'string':
            if char == '\\':
                output.append(char)
                if i + 1 < n:
                    output.append(source_text[i+1])
                    i += 2
                else:
                    i += 1
            elif char == '"':
                state = 'normal'
                output.append(char)
                i += 1
            else:
                output.append(char)
                i += 1
                
        elif state == 'compiler_directive':
            if char == '\\':
                output.append(char)
                if i + 1 < n:
                    output.append(source_text[i+1])
                    i += 2
                else:
                    i += 1
            elif char == '\n':
                state = 'normal'
                output.append(char)
                i += 1
            else:
                output.append(char)
                i += 1
                
        elif state == 'line_comment':
            if char == '\n':
                comment_str = "".join(comment_buf)
                has_keyword = any(kw in comment_str.lower() for kw in keywords)
                if has_keyword:
                    output.append("//")
                    output.append(comment_str)
                else:
                    # Replace '//' and content with equivalent spaces
                    output.append(" " * (2 + len(comment_str)))
                output.append('\n')
                state = 'normal'
                i += 1
            else:
                comment_buf.append(char)
                i += 1
                
        elif state == 'block_comment':
            if char == '*' and i + 1 < n and source_text[i+1] == '/':
                comment_str = "".join(comment_buf)
                has_keyword = any(kw in comment_str.lower() for kw in keywords)
                if has_keyword:
                    output.append("/*")
                    output.append(comment_str)
                    output.append("*/")
                else:
                    # Replace '/*' and '*/' with spaces, and content preserving newlines/tabs
                    replaced_buf = []
                    for c in comment_buf:
                        if c == '\n':
                            replaced_buf.append('\n')
                        elif c == '\t':
                            replaced_buf.append('\t')
                        else:
                            replaced_buf.append(' ')
                    output.append("  ")  # spaces for /*
                    output.append("".join(replaced_buf))
                    output.append("  ")  # spaces for */
                state = 'normal'
                i += 2
            else:
                comment_buf.append(char)
                i += 1
                
    # Handle EOF transitions
    if state == 'line_comment':
        comment_str = "".join(comment_buf)
        has_keyword = any(kw in comment_str.lower() for kw in keywords)
        if has_keyword:
            output.append("//")
            output.append(comment_str)
        else:
            output.append(" " * (2 + len(comment_str)))
    elif state == 'block_comment':
        comment_str = "".join(comment_buf)
        has_keyword = any(kw in comment_str.lower() for kw in keywords)
        if has_keyword:
            output.append("/*")
            output.append(comment_str)
        else:
            replaced_buf = []
            for c in comment_buf:
                if c == '\n':
                    replaced_buf.append('\n')
                elif c == '\t':
                    replaced_buf.append('\t')
                else:
                    replaced_buf.append(' ')
            output.append("  ")
            output.append("".join(replaced_buf))
            
    return "".join(output)

def strip_comments_in_file(input_path: str, output_path: str, preserve_keywords: list[str] | None = None) -> None:
    """Reads source from file, strips comments, and writes to output file."""
    with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    processed = strip_comments(content, preserve_keywords)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(processed)
