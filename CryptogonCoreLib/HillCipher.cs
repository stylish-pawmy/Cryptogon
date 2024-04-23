using System.Diagnostics;

namespace CryptogonCoreLib;

public static class HillCipher
{
    public static List<char> Scheme { get; set; } = new();

    private static string? _key;
    public static string? Key
    {
        get
        {
            if (_key is null)
            {
                throw new NullReferenceException(
                    message: "You have not set a key for encryption yet."
                );
            }

            return _key;
        }

        set
        {
            if (value is null)
            {
                throw new NullReferenceException(
                    message: "You cannot pass a null argument plaintext."
                );
            }

            foreach(char symbol in value)
            {
                if (!Scheme.Contains(symbol))
                {
                    throw new ArgumentException(
                        message: "The key cannot be composed of " +
                        "characters that have not been declared in the scheme.",
                        paramName: nameof(Key)
                    );
                }
            }

            if (value.Length % BlockSize != 0 || value.Length / BlockSize != BlockSize)
            {
                throw new ArgumentException(
                    message: "The key you have provided cannot be represented as " +
                    " a square matrix with the current Block Size.",
                    paramName: nameof(Key)
                );
            }

            _key = value;
        }
    }

    private static int _blockSize = 1;
    public static int BlockSize
    {
        get
        {
            return _blockSize;
        }
        set
        {
            if (value < 1)
            {
                throw new ArgumentOutOfRangeException();
            }

            _blockSize = value;
        }
    }

    /// <summary>
    /// Produces a cipher text based on the already set [Key] and [BlockSize] static properties
    /// using the predefined scheme of the [HillCipher] class
    /// </summary>
    /// <param name="plaintext">Plaintext</param>
    /// <returns>Ciphertext</returns>
    public static string Encrypt(string plaintext)
    {
        return "Cipher text";
    }

    public static int[,] KeyMatrix()
    {
        if (Key is null)
        {
            throw new NullReferenceException(
                message: "Key has not been set up yet."
            );
        }

        int[,] keyMatrix = new int[BlockSize, BlockSize];

        // Fill in key matrix
        for (int i = 0; i < Key.Length; i++)
        {
            keyMatrix[i / BlockSize, i % BlockSize] = Key[i];
        }

        return keyMatrix;
    }

    public static void AddSymbol(char symbol)
    {
        if (!Scheme.Contains(symbol))
        {
            Scheme.Add(symbol);
        }
        else
        {
            throw new ArgumentException(
                message: "Symbol does not exist in the scheme.",
                paramName: nameof(symbol)
            );
        }
    }

    public static void RemoveSymbole(char symbol)
    {
        if (Scheme.Contains(symbol))
        {
            Scheme.Remove(symbol);
        }
        else
        {
            throw new ArgumentException(
                message: "Symbol does not exist in the scheme.",
                paramName: nameof(symbol)
            );
        }
    }
}
