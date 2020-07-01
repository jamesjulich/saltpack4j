# saltpack4j
A (very WIP) Java implementation of the saltpack secure messaging format.

## What is saltpack, and why should I use it?
Saltpack is a secure messaging format developed by the folks at [Keybase](https://keybase.io). Saltpack4j, by extension, is a Java implementation of this spec. Saltpack can be thought of as a sort of successor to PGP. Like PGP, it uses public-key cryptography to securely encrypt messages for users. Saltpack addresses many of the shortcomings of PGP, though, including: adding repudiable encryption, better armored messaging output (cuz PGP output ugly), and the ability to add multiple recipients to a message (and do so anonymously if you so please). You can view the full spec [here](https://saltpack.org/) (it's worth a read, go check it out!).

Here's a comparison of PGP and saltpack output:

![enter image description here](https://i.imgur.com/i2Pdhft.png?1)

## How can I use this project?
saltpack4j is not ready for production. There are 4 saltpack modes specified in the [spec](https://saltpack.org), and saltpack4j currently implements only 1 (encryption). Now that the basics of saltpack4j are written, the final three modes should be much easier to implement. If you really, really want to use this in an application, though, you can compile it into a jar file (using the shadowJar task) and add it to your project dependencies, along with the correct version of [LazySodium](https://docs.lazycode.co/lazysodium/) (NaCl library). Here is the roadmap for our project:

 - Finish implementing other saltpack modes for both V1 and V2 of the saltpack spec (V1 and V2 encryption+decryption are already done!)
 - Review API, cleanup and make changes before Maven publish.
 - Release v1.0.0, publish to Maven.
 - Implement input streaming to encrypt/decrypt large amounts of data.
 - Release v1.1.0, publish to Maven.

If you just want to see saltpack4j in action, you can download a release jar and run it using the command line.

SaltpackTest.java in the test package contains a brief overview of how to interact with the saltpack4j API.

## Contributing
If you're interested in using/learning more about saltpack4j, I'd LOVE for you to contribute. This project has taught me so much: lots about encryption, how to debug applications properly, and even how to read code in a few new languages (Python and Go). If you would like to contribute, please submit a PR and contact me through my keybase account at [https://keybase.io/jamesjulich](https://keybase.io/jamesjulich) .

## A closing note
I'm very excited to be releasing this project, and I very much intend on finishing it/implementing streaming. Privacy (and by extension) access to encryption are fundamental human rights, and if I can further the cause by writing this library, I will. 

Special thanks to [Jack O' Connor](https://github.com/oconnor663) for his continued support and encouragement throughout the development of this library. ❤️

For more info on my projects, visit my Github page at [https://github.com/jamesjulich](https://github.com/jamesjulich) or my website at [https://jamesjulich.me](https://jamesjulich.me) .

## License
Saltpack4j is licensed under BSD-3-Clause. It is included with the source code.


