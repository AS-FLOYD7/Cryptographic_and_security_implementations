#include <stdio.h>      // Imports standard input/output functions to allow console printing (printf).
#include <stdint.h>     // Imports exact-width integer types (uint64_t, int64_t) for precise memory control.
#include <intrin.h>     // Imports x86 hardware intrinsics (Windows), providing the __rdtsc() function for CPU ticks.
#include <stdbool.h>    // Imports boolean macro definitions (true, false) for logical flags.

// Function: Computes the Greatest Common Divisor (GCD) using the Euclidean Algorithm.
// Math: gcd(a,b) = gcd(b, a mod b) until b = 0.
uint64_t compute_gcd(uint64_t a, uint64_t b) { // Defines function taking two 64-bit unsigned integers.
    uint64_t temp;                             // Declares a temporary variable for the swap operation.
    while (b != 0) {                           // Initiates a loop that continues until the remainder is zero.
        temp = b;                              // Temporarily stores the current divisor (b).
        b = a % b;                             // Updates b to be the remainder of a divided by b (modulo operation).
        a = temp;                              // Updates a to the previous divisor, shifting the sequence.
    }                                          // Ends the while loop when the exact divisor is found.
    return a;                                  // Returns the last non-zero remainder, which is the GCD.
}                                              // Ends the function scope.

// Function: Extended Euclidean Algorithm to find the Modular Multiplicative Inverse.
// Math: Finds 'd' such that (e * d) = 1 (mod phi). It solves e*x + phi*y = gcd(e, phi) = 1.
int64_t mod_inverse(int64_t e, int64_t phi) {  // Takes the public exponent (e) and totient (phi).
    int64_t t = 0, newt = 1;                   // Initializes coefficients for the Bézout identity related to 'e'.
    int64_t r = phi, newr = e;                 // Initializes remainders: r starts as phi, newr starts as e.
    while (newr != 0) {                        // Loops until the remainder reaches 0.
        int64_t quotient = r / newr;           // Calculates the integer quotient of the current division step.
        
        int64_t temp_t = t;                    // Backs up the current 't' coefficient.
        t = newt;                              // Shifts 'newt' into 't'.
        newt = temp_t - quotient * newt;       // Calculates the next 't' using the extended algorithm formula.
        
        int64_t temp_r = r;                    // Backs up the current remainder 'r'.
        r = newr;                              // Shifts 'newr' into 'r'.
        newr = temp_r - quotient * newr;       // Calculates the next remainder by subtracting quotient * newr.
    }                                          // Ends the extended Euclidean loop.
    
    if (r > 1) return -1;                      // If the final non-zero remainder is > 1, e and phi are not coprime (no inverse).
    if (t < 0) t = t + phi;                    // If the resulting inverse is negative, wraps it around into the positive modulo space.
    
    return t;                                  // Returns 't', which represents the private key 'd'.
}                                              // Ends the function scope.

// Function: Modular Exponentiation using the Square-and-Multiply (Right-to-Left Binary) algorithm.
// Math: Efficiently computes (base^exp) mod modulus in O(log exp) time to prevent integer overflow.
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) { // Takes base (message/cipher), exponent (e/d), and modulus (n).
    uint64_t result = 1;                       // Initializes the multiplicative accumulator to 1.
    base = base % mod;                         // Reduces the base modulo n before exponentiation to keep it bounded.
    while (exp > 0) {                          // Loops as long as there are bits left in the exponent.
        if (exp % 2 == 1) {                    // Checks if the least significant bit of the exponent is 1 (odd number).
            result = (result * base) % mod;    // If 1, multiplies the current base into the result and applies modulo.
        }                                      // Ends the condition for odd bits.
        exp = exp >> 1;                        // Bitwise right-shifts the exponent by 1 (divides by 2) to check the next bit.
        base = (base * base) % mod;            // Squares the base and applies modulo for the next bit position.
    }                                          // Ends the bit-processing loop.
    return result;                             // Returns the final modular exponentiation result.
}                                              // Ends the function scope.

// Main Execution
int main() {                                   // Standard C entry point.
    uint64_t start_tick, end_tick, ticks;      // Variables to store CPU Time Stamp Counter values for performance profiling.
    
    printf("\n======================================================\n"); // Prints top visual border for the console output.
    printf("     RSA CRYPTOGRAPHY SYSTEM - CPU TICK PROFILER        \n"); // Prints the title of the application.
    printf("======================================================\n\n"); // Prints bottom visual border.

    // ---------------------------------------------------------
    // STEP 1: Key Generation (Prime Selection)
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Captures the CPU hardware tick count exactly before execution.
    uint64_t p = 61;                           // Sets first prime number 'p'. (Small prime chosen for 64-bit safety).
    uint64_t q = 53;                           // Sets second prime number 'q'. (Distinct from p).
    end_tick = __rdtsc();                      // Captures the CPU tick count immediately after assignment.
    ticks = end_tick - start_tick;             // Calculates the elapsed clock cycles.
    printf("[*] Step 1: Selected primes p = %llu, q = %llu\n", p, q);     // Displays the selected mathematical primes.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // STEP 2: Compute Modulus (n)
    // Math: n = p * q. This 'n' is shared publicly as the modulus for both keys.
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Samples the hardware clock prior to multiplication.
    uint64_t n = p * q;                        // Multiplies p and q to form the RSA modulus 'n'.
    end_tick = __rdtsc();                      // Samples the hardware clock post-multiplication.
    ticks = end_tick - start_tick;             // Derives the CPU cycle cost of the multiplication.
    printf("[*] Step 2: Computed Modulus n = p * q = %llu\n", n);         // Prints the value of n.
    printf("    -> Math: The trapdoor foundation. 'n' is public.\n");     // Explains the mathematical relevance of n.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // STEP 3: Compute Euler's Totient Function phi(n)
    // Math: phi(n) = (p-1)(q-1). Counts integers up to n that are coprime to n.
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Starts the CPU cycle timer.
    uint64_t phi = (p - 1) * (q - 1);          // Calculates the totient based on Euler's formula for two primes.
    end_tick = __rdtsc();                      // Stops the CPU cycle timer.
    ticks = end_tick - start_tick;             // Calculates cycles used for the subtraction and multiplication.
    printf("[*] Step 3: Computed Euler's Totient phi(n) = %llu\n", phi);  // Displays the totient value (kept entirely secret).
    printf("    -> Math: Secret trapdoor key used to find 'd'.\n");       // Contextualizes phi's role in RSA.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // STEP 4: Choose Public Exponent (e)
    // Math: 1 < e < phi(n) and gcd(e, phi) = 1.
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Initializes CPU timer for exponent selection.
    uint64_t e = 17;                           // Selects 17 as the public exponent (commonly 3, 17, or 65537 in practice).
    uint64_t gcd_val = compute_gcd(e, phi);    // Verifies that 'e' and 'phi' share no common factors (must equal 1).
    end_tick = __rdtsc();                      // Ends CPU timer after GCD validation loop.
    ticks = end_tick - start_tick;             // Records clock cycles used by the Euclidean Algorithm.
    if (gcd_val != 1) {                        // Logic check to ensure the chosen 'e' is mathematically valid.
        printf("Error: e and phi are not coprime!\n"); // Error message if the rule is violated.
        return 1;                              // Exits the program with an error code.
    }                                          // Ends validation block.
    printf("[*] Step 4: Chose Public Exponent e = %llu\n", e);            // Prints the public exponent.
    printf("    -> Math: gcd(%llu, %llu) = 1 (Verified Coprime).\n", e, phi); // Confirms the mathematical property holds true.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // STEP 5: Compute Private Exponent (d)
    // Math: d = e^(-1) (mod phi). The private key.
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Prepares timer for the Extended Euclidean calculation.
    int64_t d = mod_inverse(e, phi);           // Executes the algorithm to find the exact modular inverse.
    end_tick = __rdtsc();                      // Captures timer upon function return.
    ticks = end_tick - start_tick;             // Computes total cycles for the inversion algorithm.
    printf("[*] Step 5: Computed Private Exponent d = %lld\n", d);        // Prints the highly sensitive private key.
    printf("    -> Math: (e * d) mod phi = (%llu * %lld) mod %llu = 1.\n", e, d, phi); // Demonstrates the inversion proof.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // DISPLAY KEYS
    // ---------------------------------------------------------
    printf("------------------------------------------------------\n"); // Prints visual separator.
    printf(" [PUBLIC KEY]  (e, n) : (%llu, %llu)\n", e, n);               // Groups e and n into the public tuple.
    printf(" [PRIVATE KEY] (d, n) : (%lld, %llu)\n", d, n);               // Groups d and n into the private tuple.
    printf("------------------------------------------------------\n\n"); // Prints visual separator.

    // ---------------------------------------------------------
    // STEP 6: Encryption
    // Math: Ciphertext C = (M ^ e) mod n
    // ---------------------------------------------------------
    uint64_t message = 42;                     // Defines the plaintext numerical message to be encrypted.
    printf("[*] Original Plaintext Message (M) = %llu\n\n", message);     // Outputs the original message to console.

    start_tick = __rdtsc();                    // Starts profiling the Square-and-Multiply encryption.
    uint64_t ciphertext = mod_exp(message, e, n); // Invokes modular exponentiation to encrypt the message.
    end_tick = __rdtsc();                      // Stops profiling post-encryption.
    ticks = end_tick - start_tick;             // Subtracts to find cycles spent encrypting.
    printf("[*] Step 6: ENCRYPTION\n");                                   // Header for encryption phase.
    printf("    -> Math: C = (M^e) mod n = (%llu^%llu) mod %llu\n", message, e, n); // Shows the explicit formula used.
    printf("    -> Ciphertext (C) = %llu\n", ciphertext);                 // Reveals the scrambled ciphertext.
    printf("    -> Clock Ticks: %llu\n\n", ticks);                        // Displays CPU time taken.

    // ---------------------------------------------------------
    // STEP 7: Decryption
    // Math: Plaintext M = (C ^ d) mod n
    // ---------------------------------------------------------
    start_tick = __rdtsc();                    // Starts profiling the decryption process (usually takes longer due to large 'd').
    uint64_t decrypted_msg = mod_exp(ciphertext, d, n); // Uses the private key 'd' to reverse the exponentiation trapdoor.
    end_tick = __rdtsc();                      // Halts the cycle timer.
    ticks = end_tick - start_tick;             // Computes CPU tick cost of decryption.
    printf("[*] Step 7: DECRYPTION\n");                                   // Header for decryption phase.
    printf("    -> Math: M = (C^d) mod n = (%llu^%lld) mod %llu\n", ciphertext, d, n); // Shows the mathematical reversal equation.
    printf("    -> Recovered Message (M) = %llu\n", decrypted_msg);       // Prints the successfully decoded plaintext.
    printf("    -> Clock Ticks: %llu\n", ticks);                          // Displays CPU time taken.

    // ---------------------------------------------------------
    // INTEGRITY CHECK
    // ---------------------------------------------------------
    printf("\n======================================================\n"); // Final border.
    if (message == decrypted_msg) {            // Logical check verifying RSA structural integrity.
        printf(" [SUCCESS] Decrypted message matches the original!\n");   // Success condition output.
    } else {                                   // Branch if mathematics broke (e.g. integer overflow).
        printf(" [FAILED] Decryption mismatch.\n");                       // Failure condition output.
    }                                          // End conditional logic.
    printf("======================================================\n"); // Final border.

    return 0;                                  // Exits main gracefully with status code 0 (success).
}                                              // End of program file.
