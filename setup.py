from distutils.core import setup

setup(
    name="pyadscore",
    python_requires=">=3.9",
    description="This is a package for working with Adscore signatures and request signing",
    keywords="adscore signature verification bot proxy",
    author="Bartosz Derleta",
    author_email="bartosz@derleta.com",
    url="https://github.com/Adscore/pyadscore",
    extras_require={
        "crypt-sodium": ["PyNaCl>=1.4.0"],
        "struct-serialize": ["phpserialize3>=0.1.4"],
        "struct-msgpack": ["msgpack>=1.0.8"],
    }
)