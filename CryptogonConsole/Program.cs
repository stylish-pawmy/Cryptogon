﻿MarkupLine("Welcome to [bold blue]Cryptogon![/] Your friendly [italic yellow](and a little outdated)[/] cryptography companion.");

HillCipher.Scheme = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray().ToList();
HillCipher.BlockSize = 3;
HillCipher.Key = "ABFGRTDXC";

MarkupLine($"The key is {HillCipher.Key}");

WriteLine(HillCipher.Encrypt("Whatever"));