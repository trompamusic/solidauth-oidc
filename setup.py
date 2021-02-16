from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="trompa-solid",
    author="Music Technology Group, Universitat Pompeu Fabra",
    install_requires=['requests', 'redis', 'PyJWT>=2.0.0'],
    description="A python library for communicating with a SOLID pod",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/trompamusic/solid-auth-demo",
    packages=['trompasolid'],
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Software Development :: Libraries"
    ],
    python_requires='>=3.7',
)
