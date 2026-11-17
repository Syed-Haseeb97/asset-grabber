# Contributing to Asset Grabber 🚀

First off, thank you for considering contributing to Asset Grabber! It’s people like you that keep the web a little more audited and developer toolkits a lot more fun.

## Code of Conduct

Be kind, respectful, and keep it productive. We’re all here to build great developer tools and roast misconfigured web servers responsibly.

## How Can I Contribute?

### 1. Reporting Bugs
- Use GitHub Issues.
- Include your browser version (Chrome/Edge/Brave).
- Include the URL or a sanitized test case if possible.
- If it crashed your browser with 10,000 images, tell us how much RAM you had left so we can laugh and then fix it.

### 2. Suggesting New Secret / Leak Patterns
Have a pattern for a new database connection string, AI model API key, or cloud provider token?
- Check `audit.js`.
- Provide regex with a sample masked test string.
- Ensure the regex does NOT cause excessive backtracking (ReDoS).

### 3. Adding New File Type Detectors
- Make sure parsing is performed purely client-side without external dependencies.
- Handle malformed or truncated responses gracefully.

## Development Setup

1. Clone your fork locally.
2. In Chrome, go to `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the repository root folder.
5. After making changes to JavaScript files, click the **Reload icon (↻)** on the extension card in `chrome://extensions`.

## Submitting Pull Requests

1. Fork the repo and create your branch from `main`.
2. Keep code style clean and vanilla—no new build steps or npm compilation required!
3. Test your changes against both clean pages and heavily nested SPAs.
4. Issue a PR with a clear summary of what you fixed or enhanced.
