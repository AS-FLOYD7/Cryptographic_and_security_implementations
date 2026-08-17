// Include the standard input/output library for printing the detailed results to the console.
#include <stdio.h>
// Include the standard library for memory allocation functions to dynamically size our arrays.
#include <stdlib.h>
// Include the complex math library to natively handle complex numbers and complex arithmetic.
#include <complex.h>
// Include the math library to access trigonometric functions necessary for calculating roots of unity.
#include <math.h>
// Include the intrin library to access __rdtsc() for exact CPU clock cycle measurements on Windows/x86.
#include <intrin.h>
// Include standard integer types for 64-bit cycle count variables.
#include <stdint.h>

// Define the mathematical constant Pi to maximum double precision for accurate angular calculations.
#define PI 3.14159265358979323846

// Core recursive Fast Fourier Transform algorithm handling both FFT and IFFT logic based on the 'inverse' flag.
void fft_core(double complex *P, int n, int inverse) {
    // Check the base case of the recursion: if array size is 1, return the constant polynomial.
    if (n == 1) return;

    // Allocate memory to hold the even-indexed coefficients (Pe) for the current recursion level.
    double complex *Pe = (double complex *)malloc((n / 2) * sizeof(double complex));
    // Allocate memory to hold the odd-indexed coefficients (Po) for the current recursion level.
    double complex *Po = (double complex *)malloc((n / 2) * sizeof(double complex));

    // Iterate through half the array size to populate the newly allocated even and odd subarrays.
    for (int i = 0; i < n / 2; i++) {
        // Extract the even-indexed elements from the parent array into Pe.
        Pe[i] = P[2 * i];
        // Extract the odd-indexed elements from the parent array into Po[cite: 1].
        Po[i] = P[2 * i + 1];
    }

    // Recursively call the FFT core function on the extracted even-indexed coefficients[cite: 1].
    fft_core(Pe, n / 2, inverse);
    // Recursively call the FFT core function on the extracted odd-indexed coefficients[cite: 1].
    fft_core(Po, n / 2, inverse);

    // Calculate the phase angle, using a negative angle for IFFT (inverse root of unity) and positive for FFT[cite: 1].
    double angle = (inverse ? -2.0 * PI / n : 2.0 * PI / n);
    // Calculate the fundamental n-th root of unity (omega) utilizing Euler's formula[cite: 1].
    double complex omega = cos(angle) + I * sin(angle);
    // Initialize the current power of the root of unity (w) starting exactly at 1[cite: 1].
    double complex w = 1.0 + 0.0 * I;

    // Iterate n/2 times to combine the results of the recursive calls back into the parent array[cite: 1].
    for (int j = 0; j < n / 2; j++) {
        // Precompute the multiplied term (w * Po[j]) to avoid redundant computations in the butterfly step[cite: 1].
        double complex w_Po = w * Po[j];
        // Apply the symmetric overlap trick to set the j-th element using addition[cite: 1].
        P[j] = Pe[j] + w_Po;
        // Apply the symmetric overlap trick to set the (j + n/2)-th element using subtraction[cite: 1].
        P[j + n / 2] = Pe[j] - w_Po;
        // Multiply the current root of unity power by omega to prepare for the next loop iteration.
        w = w * omega;
    }

    // Free the dynamically allocated memory for the even-indexed array to prevent memory leaks.
    free(Pe);
    // Free the dynamically allocated memory for the odd-indexed array to prevent memory leaks.
    free(Po);
}

// Wrapper function to execute the Forward Fast Fourier Transform cleanly[cite: 1].
void fft(double complex *P, int n) {
    // Call the core FFT function passing 0 for the inverse flag.
    fft_core(P, n, 0);
}

// Wrapper function to execute the Inverse Fast Fourier Transform cleanly[cite: 1].
void ifft(double complex *P, int n) {
    // Call the core FFT function passing 1 for the inverse flag to use the inverse root of unity[cite: 1].
    fft_core(P, n, 1);
    // Iterate over every element in the resulting evaluated array.
    for (int i = 0; i < n; i++) {
        // Scale the final interpolation results by 1/n to retrieve the correct original coefficients[cite: 1].
        P[i] /= n;
    }
}

// Define the main function where the program execution and polynomial multiplication sequence begins.
int main() {
    // Define the degree (d) of the two input polynomials we are multiplying (d = 2)[cite: 1].
    int d = 2;
    // Calculate the minimum required evaluation points to uniquely define the product polynomial, which is 2d + 1[cite: 1].
    int min_points = 2 * d + 1;
    // Initialize the padded array size variable (n) to 1.
    int n = 1;
    // Iteratively double n until it is an exact power of 2 that is greater than or equal to min_points[cite: 1].
    while (n < min_points) n *= 2; 

    // Allocate memory initialized to zero for polynomial A to natively handle zero-padding[cite: 1].
    double complex *A = (double complex *)calloc(n, sizeof(double complex));
    // Allocate memory initialized to zero for polynomial B to natively handle zero-padding[cite: 1].
    double complex *B = (double complex *)calloc(n, sizeof(double complex));
    // Allocate memory initialized to zero for the product polynomial C.
    double complex *C = (double complex *)calloc(n, sizeof(double complex));

    // Populate Polynomial A: A(x) = x^2 + 3x + 2[cite: 1].
    A[0] = 2.0 + 0.0 * I;
    A[1] = 3.0 + 0.0 * I;
    A[2] = 1.0 + 0.0 * I;

    // Populate Polynomial B: B(x) = 2x^2 + 1[cite: 1].
    B[0] = 1.0 + 0.0 * I;
    B[1] = 0.0 + 0.0 * I;
    B[2] = 2.0 + 0.0 * I;

    // Declare 64-bit unsigned integers to store the hardware CPU clock cycle counts before and after operations.
    uint64_t start_cycles, end_cycles;

    // Print the header for the coefficient to value transformation phase.
    printf("--- STEP 1: EVALUATION (Coefficient to Value Representation) ---\n");
    printf("Executing O(n log n) FFT on Polynomial A...\n");
    
    // Capture the starting CPU cycles before Polynomial A FFT.
    start_cycles = __rdtsc();
    // Execute the Forward FFT on polynomial A[cite: 1].
    fft(A, n);
    // Capture the ending CPU cycles after Polynomial A FFT.
    end_cycles = __rdtsc();
    // Print the exact CPU cycles taken for this operation.
    printf("-> Polynomial A FFT completed in %llu CPU clock cycles.\n\n", end_cycles - start_cycles);

    printf("Executing O(n log n) FFT on Polynomial B...\n");
    
    // Capture the starting CPU cycles before Polynomial B FFT.
    start_cycles = __rdtsc();
    // Execute the Forward FFT on polynomial B[cite: 1].
    fft(B, n);
    // Capture the ending CPU cycles after Polynomial B FFT.
    end_cycles = __rdtsc();
    // Print the exact CPU cycles taken for this operation.
    printf("-> Polynomial B FFT completed in %llu CPU clock cycles.\n\n", end_cycles - start_cycles);

    // Print the header for the pointwise multiplication phase.
    printf("--- STEP 2: POINTWISE MULTIPLICATION ---\n");
    printf("Multiplying corresponding y-values in O(n) time...\n");
    
    // Capture the starting CPU cycles before pointwise multiplication.
    start_cycles = __rdtsc();
    // Loop through all evaluated points up to n.
    for (int i = 0; i < n; i++) {
        // Multiply the evaluated point of A by the evaluated point of B and store it in C[cite: 1].
        C[i] = A[i] * B[i];
    }
    // Capture the ending CPU cycles after pointwise multiplication.
    end_cycles = __rdtsc();
    // Print the exact CPU cycles taken for this operation.
    printf("-> Pointwise multiplication completed in %llu CPU clock cycles.\n\n", end_cycles - start_cycles);

    // Print the header for the value to coefficient interpolation phase.
    printf("--- STEP 3: INTERPOLATION (Value to Coefficient Representation) ---\n");
    printf("Executing O(n log n) Inverse FFT on Polynomial C...\n");
    
    // Capture the starting CPU cycles before Inverse FFT.
    start_cycles = __rdtsc();
    // Execute the Inverse FFT on polynomial C to revert it to standard coefficients[cite: 1].
    ifft(C, n);
    // Capture the ending CPU cycles after Inverse FFT.
    end_cycles = __rdtsc();
    // Print the exact CPU cycles taken for this operation.
    printf("-> Polynomial C Inverse FFT completed in %llu CPU clock cycles.\n\n", end_cycles - start_cycles);

    // Print the header for the final analytical output.
    printf("--- FINAL RESULT: POLYNOMIAL C(x) = A(x) * B(x) ---\n");
    // Print the final algebraic string representation of the computed polynomial.
    printf("C(x) = %.2f + %.2fx + %.2fx^2 + %.2fx^3 + %.2fx^4\n", creal(C[0]), creal(C[1]), creal(C[2]), creal(C[3]), creal(C[4]));
    
    // Print the prefix for the raw coefficient array output.
    printf("Array Form: [");
    // Loop through the array to print the raw floating-point coefficients.
    for (int i = 0; i < n; i++) {
        // Print the real part of the coefficient, accounting for floating-point inaccuracies by rounding slightly.
        printf("%.0f%s", round(creal(C[i])), (i == n - 1) ? "" : ", ");
    }
    // Close the bracket and insert a newline for the array output.
    printf("]\n");

    // Free the memory allocated for polynomial A to clean up resources.
    free(A);
    // Free the memory allocated for polynomial B to clean up resources.
    free(B);
    // Free the memory allocated for polynomial C to clean up resources.
    free(C);

    // Return 0 to indicate the program executed and terminated successfully.
    return 0;
}
