# Contributing to Ethical Hacking Toolkit

Thank you for considering contributing to the Ethical Hacking Toolkit! We welcome all contributions, including bug reports, feature requests, documentation improvements, and code contributions.

## 📝 How to Contribute

1. **Fork the repository** and create your branch from `main`
2. **Clone the forked repository** to your local machine
3. **Set up the development environment** (see below)
4. **Make your changes** following the coding standards
5. **Test your changes** thoroughly
6. **Commit your changes** with a clear and descriptive message
7. **Push to your fork** and submit a pull request

## 🛠 Development Setup

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install development dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   ```

3. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

## 📜 Code Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions small and focused on a single responsibility
- Write unit tests for new functionality

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. A clear, descriptive title
2. Steps to reproduce the issue
3. Expected behavior
4. Actual behavior
5. Any error messages or logs
6. Your environment (OS, Python version, etc.)

## 💡 Feature Requests

We welcome feature requests! Please:

1. Check if the feature has already been requested
2. Explain why this feature would be valuable
3. Provide as much detail as possible about the proposed implementation

## 📜 Code of Conduct

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.

## 📄 License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
