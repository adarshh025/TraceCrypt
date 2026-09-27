# TraceCrypt Third-Party Software Notices & Licenses

**Product:** TraceCrypt v1.0.0  
**Licensing Status:** Commercial / Proprietary with Open Source Components  

This document lists all third-party software packages and open source libraries integrated with or distributed alongside TraceCrypt v1.0.0 in offline and air-gapped environments.

---

## 1. Third-Party Dependency Summary

| Component | Version | License | Upstream Source / Copyright |
| :--- | :--- | :--- | :--- |
| **cryptography** | 42.0.5+ | Apache-2.0 / BSD-3-Clause | Copyright (c) Individual contributors, Cryptography Developers |
| **dilithium-py** | 1.0.0+ | MIT | Copyright (c) NIST PQC Dilithium reference Python team |
| **mlkem** | 0.1.0+ | MIT / Apache-2.0 | Copyright (c) NIST PQC Kyber / ML-KEM reference Python team |
| **numpy** | 1.26.0+ | BSD-3-Clause | Copyright (c) 2005-2024, NumPy Developers |
| **scipy** | 1.12.0+ | BSD-3-Clause | Copyright (c) 2001-2024, SciPy Developers |
| **opencv-python** | 4.9.0+ | Apache-2.0 | Copyright (c) OpenCV team and contributors |
| **pillow** | 10.2.0+ | HPND | Copyright (c) 2010-2024 by Jeffrey A. Clark (Alex) and contributors |
| **pydantic** | 2.6.0+ | MIT | Copyright (c) 2017 to present, Samuel Colvin and contributors |
| **reportlab** | 4.1.0+ | BSD-3-Clause | Copyright (c) 2000-2024, ReportLab Inc. |
| **reedsolo** | 1.7.0+ | MIT | Copyright (c) 2015-2024 Tomer Filiba |
| **pyyaml** | 6.0.1+ | MIT | Copyright (c) 2017-2024 Ingy döt Net, Kirill Simonov |
| **rich** | 13.7.0+ | MIT | Copyright (c) 2020 Will McGugan |
| **typer** / **click**| 0.9.0+ | MIT / BSD-3-Clause | Copyright (c) 2014 Armin Ronacher, Sebastián Ramírez |

---

## 2. Full License Texts

### Apache License 2.0 (cryptography, opencv-python)
```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### MIT License (pydantic, rich, reedsolo, pyyaml, typer, dilithium-py, mlkem)
```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### BSD 3-Clause License (numpy, scipy, reportlab, click)
```
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
