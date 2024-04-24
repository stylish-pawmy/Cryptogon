MarkupLine("Welcome to [bold blue]Cryptogon![/] Your friendly [italic yellow](and a little outdated)[/] cryptography companion.");

HillCipher.Scheme = new Dictionary<char, int>();
string symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
for (int i = 0; i < symbols.Length; i++)
{
    HillCipher.Scheme.Add(symbols[i], i);
}

HillCipher.BlockSize = 3;
HillCipher.Key = "ABFGRTDXC";

MarkupLine($"The key is {HillCipher.Key}");

WriteLine(HillCipher.Encrypt("Whatever"));