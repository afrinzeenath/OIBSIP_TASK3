"""
Random Password Generator — Advanced (GUI) Tier
OASIS INFOBYTE — Python Programming Internship — Task 3

Features:
- tkinter GUI with a length spinbox and checkboxes for character types
- Uses the `secrets` module (cryptographically secure), not `random`
- Guarantees at least one character from each selected type
- Password strength indicator (Weak / Medium / Strong)
- "Copy to Clipboard" button using pyperclip
- Option to exclude ambiguous characters (0, O, l, 1, I)
- Session-only history of the last 5 generated passwords (never written to disk)
"""

import secrets
import string
import tkinter as tk
from tkinter import messagebox

AMBIGUOUS = "0Ol1I"


def build_charset(use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous):
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}"

    if exclude_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS)

    return charset


def generate_password(length, use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous):
    """Generate a password guaranteed to include at least one char from each selected type."""
    type_pools = []
    if use_upper:
        pool = string.ascii_uppercase
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        type_pools.append(pool)
    if use_lower:
        pool = string.ascii_lowercase
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        type_pools.append(pool)
    if use_digits:
        pool = string.digits
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS)
        type_pools.append(pool)
    if use_symbols:
        type_pools.append("!@#$%^&*()-_=+[]{}")

    if len(type_pools) < 2:
        raise ValueError("Select at least 2 character types.")
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    full_charset = build_charset(use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous)
    if not full_charset:
        raise ValueError("No characters available — check your character type selection.")

    # Guarantee one char from each selected type
    required_chars = [secrets.choice(pool) for pool in type_pools]
    remaining_length = length - len(required_chars)
    if remaining_length < 0:
        # length smaller than number of required types — pad required list instead
        required_chars = required_chars[:length]
        remaining_length = 0

    rest = [secrets.choice(full_charset) for _ in range(remaining_length)]
    password_chars = required_chars + rest

    # Shuffle securely using secrets (Fisher-Yates with secrets.randbelow)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def password_strength(password, num_types_selected):
    """Return (label, colour) strength rating based on length and character diversity."""
    length = len(password)
    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1
    score += max(0, num_types_selected - 1)

    if score <= 2:
        return "Weak", "#e74c3c"
    elif score <= 4:
        return "Medium", "#f39c12"
    else:
        return "Strong", "#2ecc71"


class PasswordGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Generator — OASIS INFOBYTE")
        self.geometry("460x560")
        self.resizable(False, False)
        self.configure(bg="#1e272e")

        self.history = []  # session-only, never persisted to disk
        self._build_widgets()

    def _build_widgets(self):
        tk.Label(
            self, text="🔐 Password Generator", font=("Segoe UI", 18, "bold"),
            bg="#1e272e", fg="#d2dae2"
        ).pack(pady=(20, 15))

        length_frame = tk.Frame(self, bg="#1e272e")
        length_frame.pack(pady=5)
        tk.Label(length_frame, text="Length:", bg="#1e272e", fg="#d2dae2",
                 font=("Segoe UI", 11)).pack(side="left", padx=5)
        self.length_var = tk.IntVar(value=12)
        tk.Spinbox(length_frame, from_=8, to=64, width=5, textvariable=self.length_var,
                   font=("Segoe UI", 11)).pack(side="left")

        types_frame = tk.LabelFrame(self, text="Character Types", bg="#1e272e",
                                     fg="#d2dae2", font=("Segoe UI", 11))
        types_frame.pack(pady=15, padx=20, fill="x")

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.exclude_ambig_var = tk.BooleanVar(value=False)

        for text, var in [
            ("Uppercase (A-Z)", self.upper_var),
            ("Lowercase (a-z)", self.lower_var),
            ("Numbers (0-9)", self.digits_var),
            ("Symbols (!@#$...)", self.symbols_var),
        ]:
            tk.Checkbutton(types_frame, text=text, variable=var, bg="#1e272e",
                           fg="#d2dae2", selectcolor="#485460",
                           font=("Segoe UI", 10)).pack(anchor="w", padx=10, pady=2)

        tk.Checkbutton(self, text="Exclude ambiguous characters (0, O, l, 1, I)",
                       variable=self.exclude_ambig_var, bg="#1e272e", fg="#d2dae2",
                       selectcolor="#485460", font=("Segoe UI", 10)).pack(pady=5)

        tk.Button(self, text="Generate Password", font=("Segoe UI", 12, "bold"),
                  bg="#0be881", fg="#1e272e", command=self.on_generate,
                  padx=15, pady=6).pack(pady=15)

        self.password_var = tk.StringVar()
        entry = tk.Entry(self, textvariable=self.password_var, font=("Consolas", 14),
                          justify="center", state="readonly", readonlybackground="#d2dae2")
        entry.pack(pady=5, padx=20, fill="x")

        self.strength_label = tk.Label(self, text="", font=("Segoe UI", 11, "bold"), bg="#1e272e")
        self.strength_label.pack(pady=5)

        tk.Button(self, text="📋 Copy to Clipboard", command=self.copy_to_clipboard,
                  font=("Segoe UI", 10)).pack(pady=5)

        tk.Label(self, text="Session History (last 5)", bg="#1e272e", fg="#d2dae2",
                 font=("Segoe UI", 10, "bold")).pack(pady=(15, 5))
        self.history_box = tk.Listbox(self, height=5, font=("Consolas", 10))
        self.history_box.pack(padx=20, fill="x")

    def on_generate(self):
        try:
            pwd = generate_password(
                self.length_var.get(),
                self.upper_var.get(), self.lower_var.get(),
                self.digits_var.get(), self.symbols_var.get(),
                self.exclude_ambig_var.get(),
            )
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return

        self.password_var.set(pwd)

        num_types = sum([
            self.upper_var.get(), self.lower_var.get(),
            self.digits_var.get(), self.symbols_var.get()
        ])
        label, colour = password_strength(pwd, num_types)
        self.strength_label.config(text=f"Strength: {label}", fg=colour)

        self.history.insert(0, pwd)
        self.history = self.history[:5]
        self.history_box.delete(0, tk.END)
        for p in self.history:
            self.history_box.insert(tk.END, p)

    def copy_to_clipboard(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Nothing to Copy", "Generate a password first.")
            return
        try:
            import pyperclip
            pyperclip.copy(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard.")
        except ImportError:
            messagebox.showerror("Missing Dependency", "pyperclip is not installed. Run: pip install pyperclip")
        except Exception as e:
            messagebox.showerror("Clipboard Error", f"Could not copy: {e}")


if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()
