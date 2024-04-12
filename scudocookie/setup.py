from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension(
            name="scudocookie",
            sources=["scudocookie.c"],
            extra_compile_args=["-msse4.2"],
        ),
    ]
)
