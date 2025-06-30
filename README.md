<h1 align="center">🛡️ XssPlayground 🛡️</h1>

<p align="center">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge" alt="PRs Welcome">
  <img src="https://img.shields.io/github/license/0x-Professor/XssPlayground?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>A safe, interactive environment to learn, test, and master Cross-Site Scripting (XSS) vulnerabilities!</b>
</p>

---

## 🚀 Features

- 🧪 **Multiple XSS Labs:** Real-world scenarios for hands-on practice.
- 🔒 **Safe by Design:** No risk to your system—fully sandboxed environment.
- 🛠️ **Custom Payloads:** Test your own XSS payloads with instant feedback.
- 📚 **Learning Resources:** Tips, guides, and write-ups for each lab.
- 🎨 **Modern UI:** Clean, responsive, and beginner-friendly interface.

---

## 📸 Demo

<p align="center">
  <img src="https://raw.githubusercontent.com/0x-Professor/XssPlayground/main/.github/demo.gif" alt="Demo GIF" width="600">
</p>

---

## 🏁 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/0x-Professor/XssPlayground.git
cd XssPlayground
```

### 2. Install dependencies

```bash
# For Python projects
pip install -r requirements.txt
```

### 3. Run the Playground

```bash
# Run the production-ready Flask app
python main.py
```

By default, the app runs on [http://localhost:5000](http://localhost:5000). Open this URL in your browser.

- For Replit: You can also run directly in a Replit environment; see `replit.md` for extra instructions.
- All challenge data is stored in Python lists in memory for demo purposes—no database setup required.

---

## 🗂️ Project Structure

```
.
├── labs/           # XSS test scenarios (15+ advanced sandboxed labs)
├── public/         # Static files and assets (JS, CSS, images)
├── src/            # Source code (Python/Flask backend, JS/HTML frontend)
│   ├── app_production.py  # Main Flask app (production)
│   ├── app_enhanced.py    # Enhanced/experimental app (may be used for staging)
│   ├── app.py             # Legacy/basic version
│   ├── main.py            # Entrypoint script
│   └── ...                # Other supporting modules
├── templates/      # Jinja2 HTML templates for the UI, labs, dashboard, payload generator, etc.
├── static/         # Custom JavaScript, CSS, and assets
├── .github/        # Workflows, issue templates, demo GIF
├── README.md       
├── replit.md       # Replit-specific setup and documentation
├── requirements.txt # Python dependencies
└── ...             # Other config files (LICENSE, etc.)
```

- **labs/**: Contains all XSS challenge definitions and scenarios, each lab sandboxed for safety.
- **src/**: Python Flask backend (main app in `app_production.py`), handles routing, session, analytics, security toggling, etc.
- **templates/**: Jinja2 HTML templates for the dashboard, challenges, analytics, payload generator, etc.
- **static/**: Frontend logic (payload logging, monitoring, UI enhancements).
- **public/**: Static served files (images, fonts, etc.).
- **.github/**: Project automation and documentation.

---

## 🎮 How to Use

1. Select a lab from the dashboard.
2. Read the scenario details and hints.
3. Enter your XSS payload in the input field.
4. Submit and observe the results.
5. Learn from feedback and try different approaches!

---

## 🌐 Live Version

> You can try the playground online soon:  
> 

---

## 🤝 Contributing

We ❤️ contributions! To get started:

1. Fork the repo and create your branch:  
   ```bash
   git checkout -b feature/your-feature
   ```
2. Make your changes and commit:  
   ```bash
   git commit -am 'Add new feature'
   ```
3. Push to your forked repo:  
   ```bash
   git push origin feature/your-feature
   ```
4. Create a new Pull Request — and don’t forget to describe your change!

**Please read our [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting.**

---

## ⭐️ Show Your Support

If you like this project, please give it a star!  
Your feedback and stars keep us going 🚀

---

## 📢 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Happy hacking, and stay safe! 🛡️</b>
</p>
