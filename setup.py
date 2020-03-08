from setuptools import setup

setup(
    name="microcorruption_loader",
    version="0.1",
    description=(
        "A Loader for angr which reads the memory dumps "
        "from the microcorruption CTF."
    ),
    py_modules=["microcorruption_loader"],
    install_requires=["construct", "angr", "angr-platforms"],
    dependency_links=["https://github.com/angr/angr-platforms.git"],
)
