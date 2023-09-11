# cis2salt

## Goals
Convert CIS XCCDF Benchmark files to saltstack states as automated as possible

## State
As of now the python code written can successfully parse Windows Server 2016 to Windows Server 2022 CIS Benchmarks in their respective XCCDF format.

## Disclaimer
Honestly, I am no scripter, neither a programmer. This happened in my free time and the code base is probably a mess in eyes of developers. Feel free to fork it.


## bits_util function
In some states I worked with the "lesser than or equal", "Greater than of equal" from the CIS Recommendation. Since Salt itself can only express one value in a strict manner, I implemented a saltstack module which allowes me to check, whether the system value is in an allowed state.
