from __future__ import annotations

import math, statistics
import secrets
from dataclasses import dataclass
from typing import Dict, List

import typer
import unidecode
from wordfreq import top_n_list

# Try to use the best available zxcvbn implementation for password strength analysis
try:
    from zxcvbn import password_strength as _zx

    # Analyse the password using zxcvbn
    def _analyse(pwd: str) -> Dict:
        return _zx(pwd)

    # Get entropy value from analysis
    def _entropy(info: Dict) -> float:
        return info.get("entropy", info["guesses_log10"] * math.log2(10))
except (ImportError, AttributeError):
    from zxcvbn import zxcvbn as _zx

    def _analyse(pwd: str) -> Dict:
        return _zx(pwd)

    def _entropy(info: Dict) -> float:
        return info["guesses_log10"] * math.log2(10)

# Constants
SPECIAL_CHARS = "!@#$%^&*()"
_WORDLIST_CACHE: Dict[str, List[str]] = {} # Cached wordlists for performance
_rng = secrets.SystemRandom() # Secure random  number generator
MAX_LENGTH = 72
MAX_CUSTOM_WORD_LENGTH = 15 # Max length of custom user word

# Get a list of top words (for selected language)
def _get_wordlist(lang: str, n: int = 5000) -> List[str]:
    if lang in _WORDLIST_CACHE:
        return _WORDLIST_CACHE[lang]
    words = [unidecode.unidecode(w).lower() for w in top_n_list(lang, n)]
    words = [w for w in words if w.isascii() and w.isalpha()]
    _WORDLIST_CACHE[lang] = words
    return words

# Select a secure random element from the sequence
def _secure_choice(seq):
    return _rng.choice(seq)

# Validate custom number input is numeric
def _valid_number(token: str | None) -> str | None:
    return token.strip() if token and token.strip().isdigit() else None

# Validate custom special character input is allowed
def _valid_special(token: str | None) -> str | None:
    return token.strip() if token and token.strip() in SPECIAL_CHARS else None

# Dataclass to hold all passphrase configuration options
@dataclass(slots=True)
class PassphraseOptions:
    words: int = 4
    lang: str = "en"
    include_number: bool = True
    number_mode: str = "Random"
    custom_number: str | None = None
    include_special: bool = True
    special_mode: str = "Random"
    custom_special: str | None = None
    include_spaces: bool = True
    custom_word: str | None = None
    enforce_complexity: bool = True

    # Return delimiter based on user option
    def delimiter(self) -> str:
        return " " if self.include_spaces else ""

# Main function: generate a  passphrase
def generate_passphrase(opts: PassphraseOptions) -> str:
    wordlist = _get_wordlist(opts.lang)

    # Pick words from the wordlist securely
    parts = (
        _rng.sample(wordlist, opts.words)
        if opts.words <= len(wordlist)
        else [_secure_choice(wordlist) for _ in range(opts.words)]
    )

    # If a custom word is provided - insert it at a random index
    if opts.custom_word:
        custom = opts.custom_word.strip()[:MAX_CUSTOM_WORD_LENGTH]
        parts[_rng.randrange(len(parts))] = custom

    # Capitalize one random word
    idx_cap = _rng.randrange(len(parts))
    parts[idx_cap] = parts[idx_cap].capitalize()

    # Helper to insert a token randomly
    def _insert_random(token: str):
        parts.insert(_rng.randrange(len(parts) + 1), token)

    # Insert number (if required)
    if opts.include_number or opts.enforce_complexity:
        number_token = _valid_number(opts.custom_number) if opts.number_mode == "Custom" else None
        if number_token:
            number = number_token
        else:
            digit_len = _rng.choice([1, 2, 3, 4])
            number = str(_rng.randrange(10 ** (digit_len - 1), 10 ** digit_len))
        _insert_random(number)

    # Insert special character (if required)
    if opts.include_special or opts.enforce_complexity:
        special_token = _valid_special(opts.custom_special) if opts.special_mode == "Custom" else None
        _insert_random(special_token or _secure_choice(SPECIAL_CHARS))

    # Join the final passphrase string
    candidate = opts.delimiter().join(parts)

    # If no spaces allowed: shuffle phrases and concatenate them
    if not opts.include_spaces:
        token_list = candidate.split()
        _rng.shuffle(token_list)
        candidate = "".join(token_list)

    # Ensure passphrase doesn't exceed allowed maximum length
    if len(candidate) > MAX_LENGTH:
        raise ValueError(f"Generated passphrase exceeds max length ({MAX_LENGTH} characters). Try fewer words or disable extras.")

    # If complexity is required: recursively try again until a strong one is created
    if opts.enforce_complexity and not meets_complexity(candidate):
        return generate_passphrase(opts)

    return candidate

# Use zxcvbn to ensure passphrase meets strength requirements
def meets_complexity(pwd: str) -> bool:
    info = _analyse(pwd)
    return info["guesses_log10"] >= 8 and len(pwd) >= 15

# Set up Typer command-line interface
app = typer.Typer(add_help_option=True, help="Generate entropy‑based passphrases from the terminal.")

# CLI command to generate new passphrase with configuration
@app.command("new", help="Print one or more passphrases to stdout.")
def new(
    words: int = typer.Option(4, "--words", min=2, max=8, help="Number of words"),
    count: int = typer.Option(1, "--count", min=1, max=50, help="How many to generate"),
    lang: str = typer.Option("en", "--lang", help="Language code"),
    number: str = typer.Option(None, "--number", help="Custom digits"),
    special: str = typer.Option(None, "--special", help="Custom special char"),
):
    # Convert CLI options to passphrase configuration
    opts = PassphraseOptions(
        words=words,
        lang=lang,
        include_number=True,
        number_mode="Custom" if number else "Random",
        custom_number=number,
        include_special=True,
        special_mode="Custom" if special else "Random",
        custom_special=special,
    )

    # Print each generated passphrase to the terminal
    for _ in range(count):
        try:
            typer.echo(generate_passphrase(opts))
        except Exception as e:
            typer.secho(f"Error: {e}", fg=typer.colors.RED)

# Web interface
def streamlit_ui():
    import streamlit as st

    st.set_page_config(page_title="Passphrase Generator", page_icon="🔐", layout="centered")
    st.title("🔐 Passphrase Generator")

    with st.expander("ℹ️ How to use this tool", expanded=False):
        st.markdown("""
        - This tool generates secure, readable passphrases.
        - Toggle **Enforce complexity** for passwords suitable for Active Directory or policy-enforced systems.
        - If not enforced, you can adjust the format for easier memorability.
        - Use the CSV download to save multiple passphrases.
        """)

    with st.sidebar:
        st.header("Options")
        lang = st.selectbox("Language", ["en", "af", "es", "de", "fr", "it", "pt", "nl", "sv"], index=0)
        enforce_complexity = st.toggle("Enforce complexity", value=True)

        include_number = True
        include_special = True
        include_spaces = True
        custom_word = None
        custom_number = None
        custom_special = None
        number_mode = "Random"
        special_mode = "Random"

        if enforce_complexity:
            default_words = 2
        else:
            include_number = st.toggle("Include number", value=True)
            include_special = st.toggle("Include special", value=True)
            include_spaces = st.toggle("Spaces between words", value=True)
            default_words = 4 if not include_spaces else 3

            with st.expander("⚙️ Advanced Settings"):
                custom_word = st.text_input("Custom word", help="Max 15 characters").strip() or None
                if custom_word and len(custom_word) > MAX_CUSTOM_WORD_LENGTH:
                    st.error(f"Custom word too long. Max is {MAX_CUSTOM_WORD_LENGTH} characters.")

                if include_number:
                    number_mode = st.radio("Number mode", ["Random", "Custom"], horizontal=True)
                    if number_mode == "Custom":
                        custom_number = st.text_input("Custom number (digits only)")

                if include_special:
                    special_mode = st.radio("Special mode", ["Random", "Custom"], horizontal=True)
                    if special_mode == "Custom":
                        custom_special = st.text_input("Custom symbol", max_chars=1)

            if not include_number or not include_special:
                st.warning("⚠️ Password may not meet Active Directory complexity requirements.")

        word_count = st.slider("Number of words", 2, 8, value=default_words)
        count = st.number_input("How many passphrases?", 1, 20, value=3)

        opts = PassphraseOptions(
            words=word_count,
            lang=lang,
            include_number=include_number,
            number_mode=number_mode,
            custom_number=custom_number,
            include_special=include_special,
            special_mode=special_mode,
            custom_special=custom_special,
            include_spaces=include_spaces,
            custom_word=custom_word,
            enforce_complexity=enforce_complexity,
        )

        test_samples = []
        errors = []
        
        # Try to generate 10 valid samples, but skip ones that raise errors
        for _ in range(10): # THIS WAS 5
            try:
                sample = generate_passphrase(opts) 
                test_samples.append(sample)
            except Exception as e:
                errors.append(str(e))

        if test_samples:
            max_estimated_length = max(len(p) for p in test_samples)
            avg_estimated_length = sum(len(p) for p in test_samples) // len(test_samples)
            median_estimated_length = statistics.median(len(p) for p in test_samples)
        else:
            max_estimated_length = 0
            avg_estimated_length = 0
            median_estimated_length = 0
        st.info(f"Estimated Characters: avg: {avg_estimated_length}, median: {median_estimated_length}, max: {max_estimated_length}")
        if max_estimated_length > MAX_LENGTH - 4:
            st.warning(f"Max estimated length may exceed {MAX_LENGTH} characters. Try fewer words.")

    

    def entropy_label(entropy: float) -> str:
        if entropy < 30:
            return "🔴 Weak"
        elif entropy < 45:
            return "🟠 Moderate"
        elif entropy < 60:
            return "🟢 Strong"
        else:
            return "🔵 Excellent"

    def entropy_color(entropy: float) -> str:
        if entropy < 30:
            return "red"
        elif entropy < 45:
            return "orange"
        elif entropy < 60:
            return "green"
        else:
            return "blue"

    if st.button("🔐 Generate Passphrases", use_container_width=True):
        try:
            pwds = [generate_passphrase(opts) for _ in range(int(count))]
        except Exception as e:
            st.error(f"Error: {e}")
            return

        st.success(f"Generated {len(pwds)} passphrase(s)")
        csv = "\n".join(pwds)
        st.download_button("📄 Download CSV", csv, "passphrases.csv", "text/csv")

        for idx, p in enumerate(pwds, 1):
            info = _analyse(p)
            entropy_bits = _entropy(info)
            strength = entropy_label(entropy_bits)
            colour = entropy_color(entropy_bits)

            st.markdown(f"### 🔐 Passphrase #{idx}")
            st.code(p, language="text")
            st.markdown(
                f"<span style='color:{colour}; font-weight:bold'>Strength: {strength} ({entropy_bits:.2f} bits)</span>",
                unsafe_allow_html=True,
            )
            st.progress(min(int(entropy_bits * 2), 100), text=f"{entropy_bits:.2f} bits")
            st.divider()

if __name__ == "__main__":
    try:
        import streamlit as _st
        streamlit_ui()
    except ModuleNotFoundError:
        app()
