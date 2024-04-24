using System.Diagnostics;
using System.Security.Authentication.ExtendedProtection;
using System.Linq;
using System.Numerics;

namespace CryptogonCoreLib;

public static class HillCipher
{
    public static Dictionary<char, int> Scheme { get; set; } = new();

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

            foreach (char symbol in value)
            {
                if (!Scheme.Keys.Contains(symbol))
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

            string tmp = _key;
            _key = value;

            if (!IsInvertible(KeyMatrix()))
            {
                _key = tmp;
                throw new ArgumentException(
                    message: "The provided key results in a non invertible matrix."
                );
            }
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
        // Retrieve key matrix
        int[,] keyMatrix = KeyMatrix();

        // Retrieve plaintext blocks
        List<int[]> plaintextBlocks = new();
        for (int i = 0; i < plaintext.Length; i += BlockSize)
        {
            plaintextBlocks.Add(GetBlockVector(plaintext, i / BlockSize));
        }

        // Calculate cipher text blocks
        List<int[]> ciphertextBlocks = new();
        foreach (int[] plaintextBlock in plaintextBlocks)
        {
            int[] ciphertextBlock = NormalizeVector(
                MultiplyMatrixByVector(keyMatrix, plaintextBlock),
                Scheme.Keys.Count
            );
            
            ciphertextBlocks.Add(ciphertextBlock);
        }

        string ciphertext = "";
        foreach(int[] ciphertextBlock in ciphertextBlocks)
        {
            for (int i = 0; i < ciphertextBlock.Length; i++)
            {
                ciphertext += Scheme
                .FirstOrDefault(symbol => symbol.Value == ciphertextBlock[i])
                .Key;
            }
        }

        return ciphertext;
    }

    public static string Decrypt(string ciphertext)
    {
        // Retrieve decryption key matrix
        int[,] keyMatrix = InvertMatrix(KeyMatrix());

        // Retrieve ciphertext blocks
        List<int[]> ciphertextBlocks = new();
        for (int i = 0; i < ciphertext.Length; i += BlockSize)
        {
            ciphertextBlocks.Add(GetBlockVector(ciphertext, i / BlockSize));
        }

        // Calculate plaintext blocks
        List<int[]> plaintextBlocks = new();
        foreach (int[] ciphertextBlock in ciphertextBlocks)
        {
            int[] plaintextBlock = NormalizeVector(
                MultiplyMatrixByVector(keyMatrix, ciphertextBlock),
                Scheme.Keys.Count
            );
            
            plaintextBlocks.Add(plaintextBlock);
        }

        string plaintext = "";
        foreach(int[] plaintextBlock in plaintextBlocks)
        {
            for (int i = 0; i < plaintext.Length; i++)
            {
                ciphertext += Scheme
                .FirstOrDefault(symbol => symbol.Value == plaintextBlock[i])
                .Key;
            }
        }

        return plaintext;
    }

    /// <summary>
    /// Returns a block from a string following the specified BlockSize
    /// and given a block index
    /// </summary>
    /// <returns></returns>
    private static int[] GetBlockVector(string text, int index)
    {
        string blockText = (text.Length - index * BlockSize < BlockSize)
        ? text.Substring(
            Math.Min(text.Length, index * BlockSize),
            Math.Min(text.Length, text.Length - index * BlockSize)
        )
        : text.Substring(
            index * BlockSize,
            BlockSize
        );

        if (blockText.Length == 0)
        {
            throw new ArgumentOutOfRangeException();
        }

        while (blockText.Length < BlockSize)
        {
            blockText += 'Z';
        }

        return blockText
        .Select(symbol => Scheme[symbol])
        .ToArray();
    }

    /// <summary>
    /// Generates a key matrix based on the already stored Key
    /// </summary>
    /// <returns>Key Matrix</returns>
    /// <exception cref="NullReferenceException"></exception>
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
            keyMatrix[i / BlockSize, i % BlockSize] = Scheme[Key[i]];
        }

        return keyMatrix;
    }

    public static int[] MultiplyMatrixByVector(int[,] matrix, int[] vector)
    {
        var result = new int[vector.Length];

        for (int i = 0; i < matrix.GetLength(0); i++)
        {
            int sum = 0;
            for (int j = 0; j < matrix.GetLength(1); j++)
            {
                sum += matrix[i, j] * vector[j];
            }

            result[i] = sum;
        }

        return result;
    }

    public static int[] NormalizeVector(int[] vector, int cap)
    {
        var result = new int[vector.Length];
        for (int i = 0; i < vector.Length; i++)
        {
            result[i] = vector[i] % cap;
        }

        return result;
    }

    public static bool IsInvertible(int[,] matrix)
    {
        return CalculateDeterminant(matrix) != 0;
    }

    public static int[,] InvertMatrix(int[,] matrix)
    {
        if (!IsInvertible(matrix))
        {
            throw new ArgumentException(
                message: "The matrix provided cannot be inverted."
            );
        }

        int n = matrix.GetLength(0);
        int[,] result = new int[n, n];
        double[,] identity = GetIdentityMatrix(n);
        double[,] augmentedMatrix = new double[n, 2 * n];

        // Create augmented matrix [matrix | identity]
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                augmentedMatrix[i, j] = matrix[i, j];
                augmentedMatrix[i, j + n] = identity[i, j];
            }
        }

        // Apply Gauss-Jordan Elimination
        for (int i = 0; i < n; i++)
        {
            // Find pivot for column i
            int max = i;
            for (int j = i + 1; j < n; j++)
            {
                if (Math.Abs(augmentedMatrix[j, i]) > Math.Abs(augmentedMatrix[max, i]))
                {
                    max = j;
                }
            }

            // Swap rows i and max
            double[] temp = new double[2 * n];
            for (int j = 0; j < 2 * n; j++)
            {
                temp[j] = augmentedMatrix[i, j];
                augmentedMatrix[i, j] = augmentedMatrix[max, j];
                augmentedMatrix[max, j] = temp[j];
            }

            // Make pivot value (augmentedMatrix[i, i]) equal to 1
            double pivot = augmentedMatrix[i, i];
            for (int j = 0; j < 2 * n; j++)
            {
                augmentedMatrix[i, j] /= pivot;
            }

            // Make all other values in column i equal to 0
            for (int j = 0; j < n; j++)
            {
                if (j != i)
                {
                    double ratio = augmentedMatrix[j, i];
                    for (int k = 0; k < 2 * n; k++)
                    {
                        augmentedMatrix[j, k] -= ratio * augmentedMatrix[i, k];
                    }
                }
            }
        }

        // Extract the result (inverse matrix)
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                result[i, j] = (int) Math.Round(augmentedMatrix[i, j + n]);
            }
        }

        return result;
    }

    /// <summary>
    /// Generates an identity matrix of dimension n
    /// </summary>
    /// <param name="n"></param>
    /// <returns>Identity Matrix</returns>
    public static double[,] GetIdentityMatrix(int n)
    {
        double[,] identityMatrix = new double[n, n];

        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                identityMatrix[i, j] = (i == j) ? 1 : 0;
            }
        }

        return identityMatrix;
    }

    /// <summary>
    /// Calculates the determinant of a matrix
    /// </summary>
    /// <param name="matrix"></param>
    /// <param name="initialFactor"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    public static float CalculateDeterminant(int [,] matrix, int initialFactor = 1)
    {
        if (!(matrix.GetLength(0) == matrix.GetLength(1)))
        {
            throw new ArgumentException(
                message: "The provided matrix is not square."
            );
        }

        switch (matrix.GetLength(0))
        {
            case 0:
                return 0;
            case 1:
                return matrix[0, 0];
            case 2:
                return matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            default:
                // Sum of sub determinants
                float sum = 0;
                // Iterate through super matrix columns
                for (int i = 0; i < matrix.GetLength(1); i++)
                {
                    // Get the sub matrix without the current column
                    int[,] subMatrix = new int[matrix.GetLength(0) - 1, matrix.GetLength(1) - 1];
                    for (int j = 0; j < subMatrix.GetLength(0); j++)
                    {
                        int h = 0;
                        int k = 0;
                        // Map values to the sub matrix
                        while (h < matrix.GetLength(1) && k < subMatrix.GetLength(0))
                        {
                            // Ignore the current column
                            if (h == i)
                            {
                                h++;
                            }

                            subMatrix[j, k] = matrix[j + 1, h];
                            h++;
                            k++;
                        }
                    }

                    // Get the sum with respecting the sign of the column
                    sum += CalculateDeterminant(subMatrix, matrix[1, i] * (int) Math.Pow(-1, i));
                }
                return sum * initialFactor;
        }
    }
}
