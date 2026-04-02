# Shell Completions

shadowforge can generate tab-completion scripts for all major shells.

## Usage

```bash
shadowforge completions <SHELL>
```

Where `<SHELL>` is one of: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

You can also write directly to a file:

```bash
shadowforge completions bash --output ~/.local/share/bash-completion/completions/shadowforge
```

## Bash

```bash
# Add to ~/.bashrc or ~/.bash_profile
eval "$(shadowforge completions bash)"
```

Or install persistently:

```bash
shadowforge completions bash > ~/.local/share/bash-completion/completions/shadowforge
```

## Zsh

```bash
# Add to ~/.zshrc (before compinit)
eval "$(shadowforge completions zsh)"
```

Or install to your completions directory:

```bash
shadowforge completions zsh > ~/.zfunc/_shadowforge
# Ensure ~/.zfunc is in your fpath:
# fpath=(~/.zfunc $fpath)
```

## Fish

```bash
shadowforge completions fish > ~/.config/fish/completions/shadowforge.fish
```

## Elvish

```bash
eval (shadowforge completions elvish | slurp)
```

## PowerShell

```powershell
shadowforge completions powershell | Out-String | Invoke-Expression

# Or add to your $PROFILE:
shadowforge completions powershell >> $PROFILE
```
