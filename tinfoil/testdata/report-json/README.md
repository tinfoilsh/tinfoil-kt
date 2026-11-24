# Golden files for the report's JSON form

These files are copied unchanged from tinfoil-go's
`verify/testdata/report-json` (tinfoilsh/tinfoil-go#346), where tinfoil-go
checks its own encoder against them. Copy them again from there when the
form changes; do not edit them here.

Each file is one case of the JSON form that `VerificationReport.toJson()`
writes:

- `description` says what the case shows.
- `vector`, when present, names a full-verify vector of the shared
  conformance suite, relative to its `vectors/` directory. The case's report
  is what verifying that vector gives, at the vector's verification time.
- `report` is the expected JSON form.

`ReportJsonTest` reads every file's report as the verifier library would
return it and writes it again. `ConformanceVectorTest`, in the conformance
build, verifies each file's vector and compares the report that it writes
with the file's.

A comparison is of JSON values, not bytes, and leaves out the step messages,
which are each SDK's own text, and `metadata`, which describes the run. It
compares times as instants.
