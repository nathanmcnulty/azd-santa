# Assessment fixture; no runtime adoption

`Azd.GraphAuthentication.psm1` is an unchanged public-domain source capture from
[azd-reference a29e222181ce8cdce5de148cf88e39bd3202cf91](https://github.com/nathanmcnulty/azd-reference/blob/a29e222181ce8cdce5de148cf88e39bd3202cf91/components/powershell/graph-delegated-authentication/Azd.GraphAuthentication.psm1),
component `graph-delegated-authentication` 0.1.1.

Its SHA-256 over UTF-8 LF bytes is
`F727F0680A6F11BE057D5A0993C6FEC9917D7DE8870685427A5EC8CA4D739B5E`.
The [original manifest](https://github.com/nathanmcnulty/azd-reference/blob/a29e222181ce8cdce5de148cf88e39bd3202cf91/components/powershell/graph-delegated-authentication/Azd.GraphAuthentication.psd1)
declares the Unlicense/public-domain release and Microsoft.Graph.Authentication
2.30.0 as a dependency. Tests import the module source directly with closed
mocked SDK functions; they do not load that dependency or authenticate.

Only `tests/Santa.GraphCompatibility.Tests.ps1` imports this fixture. Neither
publisher imports it. This is not a runtime vendor package, component lock,
permission grant, or adoption approval. New assessment validation targets
PowerShell 7.6 or later; the upstream manifest's historical minimum is not a
compatibility target for this assessment.
