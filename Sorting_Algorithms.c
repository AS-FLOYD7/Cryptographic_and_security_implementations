#include <stdio.h> // Includes standard I/O library for printf and file operations, setting up for the next include.
#include <stdlib.h> // Includes standard library for malloc, free, and rand, following the standard I/O inclusion.
#include <time.h> // Includes time library for clock() to measure performance ticks, following stdlib.h.
#include <string.h> // Includes string library for memcpy to duplicate arrays efficiently, following time.h.
#include <math.h> // Includes math library for log2() to calculate the time complexity constants, following string.h.

unsigned long long current_comps = 0; // Declares and initializes a global counter for element comparisons, preceding the swaps counter.
unsigned long long current_swaps = 0; // Declares and initializes a global counter for element swaps/writes, following the comparisons counter.

void swap(int *a, int *b) { // Defines a unified swap function using pointers, used primarily by Heap and Quick sort.
    int t = *a; // Dereferences pointer 'a' and stores its value in a temporary integer variable 't'.
    *a = *b; // Overwrites the value at memory location 'a' with the value from memory location 'b'.
    *b = t; // Places the original value of 'a' (stored in 't') into the memory location 'b', completing the swap.
    current_swaps++; // Increments the global swaps tracker to accurately benchmark write operations.
} // Ends the swap function block, returning control to the caller.

/* ============================ MERGE SORT ============================ */ // Visual separator and label for the Merge Sort section.
void merge(int arr[], int temp[], int l, int m, int r) { // Merges two sorted subarrays using a pre-allocated temp array to eliminate malloc overhead.
    int i = l, j = m + 1, k = l; // Initializes tracking pointers for the left subarray (i), right subarray (j), and temp array (k).
    while (i <= m && j <= r) { // Starts a loop that continues as long as both the left and right halves have unmerged elements remaining.
        current_comps++; // Increments the comparison counter for the upcoming if-statement check.
        if (arr[i] <= arr[j]) { // Compares the current elements of both halves to find the smaller value.
            temp[k++] = arr[i++]; // Copies the left element into the temp array and post-increments both pointers since it was smaller.
        } else { // Handles the alternate case where the right element is strictly smaller.
            temp[k++] = arr[j++]; // Copies the right element into the temp array and post-increments both pointers.
        } // Closes the else block, concluding the conditional placement for this single loop iteration.
        current_swaps++; // Increments the swaps counter to track the array write operation that just occurred above.
    } // Ends the main merging while-loop, moving on to handle any leftover elements in either half.
    
    while (i <= m) { temp[k++] = arr[i++]; current_swaps++; } // Loops to copy any remaining left-half elements into temp, tracking each write.
    while (j <= r) { temp[k++] = arr[j++]; current_swaps++; } // Loops to copy any remaining right-half elements into temp, tracking each write.
    
    for (i = l; i <= r; i++) { // Iterates over the actively merged segment bounds to copy data back to the original array.
        arr[i] = temp[i]; // Writes the sorted element from the temporary array back into the original array structure.
        current_swaps++; // Increments the swap/write counter to record this final write-back step.
    } // Ends the for loop, completing the entire merge process for this recursion level.
} // Ends the optimized merge function.

void mergeSortHelper(int arr[], int temp[], int l, int r) { // A recursive helper function to continuously pass the single temp array downwards.
    if (l < r) { // Checks if the current array segment has more than one element; if so, it needs sorting.
        int m = l + (r - l) / 2; // Calculates the midpoint safely to avoid integer overflow during calculation.
        mergeSortHelper(arr, temp, l, m); // Recursively calls itself to sort the left half of the current segment.
        mergeSortHelper(arr, temp, m + 1, r); // Recursively calls itself to sort the right half of the current segment, following the left.
        merge(arr, temp, l, m, r); // Calls the merge function to combine the two newly sorted halves together.
    } // Ends the base-case conditional check.
} // Ends the recursive helper function.

void mergeSort(int arr[], int l, int r) { // The main public wrapper for Merge Sort that handles the one-time memory allocation.
    int *temp = (int *)malloc((r - l + 1) * sizeof(int)); // Allocates dynamic memory for the temporary array ONCE, optimizing away thousands of allocations.
    mergeSortHelper(arr, temp, l, r); // Initiates the recursive sorting process by calling the helper function with the allocated array.
    free(temp); // Frees the dynamically allocated temporary array after sorting is completely finished to prevent memory leaks.
} // Ends the mergeSort wrapper function.

/* ============================ HEAP SORT ============================= */ // Visual separator and label for the Heap Sort section.
void heapify(int arr[], int n, int i) { // Transforms a targeted subtree into a max-heap using an optimized iterative approach instead of recursion.
    int largest; // Declares an integer to track the index containing the largest value among a parent and its children.
    while (1) { // Initiates an infinite loop to sift elements down the tree iteratively until the heap property is restored.
        largest = i; // Assumes initially that the current parent node is the largest element.
        int left = 2 * i + 1; // Computes the mathematical array index for the left child of the current node.
        int right = 2 * i + 2; // Computes the mathematical array index for the right child of the current node.

        if (left < n) { // Validates if the calculated left child index actually exists within the bounds of the heap.
            current_comps++; // Increments the global comparison tracker before evaluating the values.
            if (arr[left] > arr[largest]) largest = left; // Updates 'largest' to the left child's index if its value is greater.
        } // Closes the left child evaluation block.
        if (right < n) { // Validates if the calculated right child index exists within the heap bounds.
            current_comps++; // Increments the global comparison tracker prior to evaluating the right child's value.
            if (arr[right] > arr[largest]) largest = right; // Updates 'largest' to the right child's index if it possesses the highest value so far.
        } // Closes the right child evaluation block.

        if (largest != i) { // Checks if either child turned out to be larger than the initial parent node.
            swap(&arr[i], &arr[largest]); // Swaps the parent element with its largest child to enforce the max-heap rule.
            i = largest; // Updates the current index 'i' to the child's old index to continue sifting down in the next loop cycle.
        } else { // Executes if the parent was already larger than both children (or has no children).
            break; // Breaks out of the infinite while-loop because the sub-tree satisfies the heap property.
        } // Closes the conditional logic determining whether to continue sifting down or stop.
    } // Closes the iterative while-loop.
} // Ends the optimized iterative heapify function.

void heapSort(int arr[], int n) { // Main function to execute Heap Sort on a given array.
    for (int i = n / 2 - 1; i >= 0; i--) // Loops backwards from the last non-leaf node up to the root node.
        heapify(arr, n, i); // Calls heapify on each node to construct the initial valid max-heap structure from the raw array.

    for (int i = n - 1; i > 0; i--) { // Loops backwards from the end of the array down to the second element.
        swap(&arr[0], &arr[i]); // Swaps the maximum element (at root index 0) to its final sorted position at the end of the current heap.
        heapify(arr, i, 0); // Calls heapify on the new root to restore the max-heap property for the remaining unsorted elements.
    } // Closes the main sorting loop.
} // Ends the heapSort function.

/* ============================ QUICK SORT ============================ */ // Visual separator and label for the Quick Sort section.
int partition(int arr[], int low, int high) { // Reorders the array segment around a pivot, returning the pivot's final index location.
    int mid = low + (high - low) / 2; // Calculates the midpoint index to utilize median-of-three pivot selection logic.
    
    current_comps++; if (arr[mid] < arr[low])  swap(&arr[mid], &arr[low]); // Starts median finding: swaps low and mid if low is greater, tracking the comparison.
    current_comps++; if (arr[high] < arr[low]) swap(&arr[high], &arr[low]); // Continues median finding: guarantees the lowest index holds the smallest value.
    current_comps++; if (arr[high] < arr[mid]) swap(&arr[high], &arr[mid]); // Concludes median finding: mid now definitely holds the median of the three values.
    swap(&arr[mid], &arr[high]); // Moves the calculated median value into the high index slot to act as the partition pivot.

    int pivot = arr[high]; // Assigns the actual integer value of the pivot for rapid comparisons in the upcoming loop.
    int i = low - 1; // Initializes the boundary index 'i' for smaller elements just below the starting 'low' index.
    
    for (int j = low; j < high; j++) { // Iterates through the partition from the lowest index up to the element just before the pivot.
        current_comps++; // Logs the impending comparison operation against the pivot.
        if (arr[j] < pivot) { // Checks if the currently evaluated element is smaller than the pivot value.
            i++; // Expands the region of smaller elements by incrementing the 'i' boundary index.
            if (i != j) swap(&arr[i], &arr[j]); // OPTIMIZATION: Swaps elements only if they are distinct indices, preventing redundant memory writes.
        } // Ends the conditional block handling elements smaller than the pivot.
    } // Ends the partitioning for-loop.
    
    if (i + 1 != high) swap(&arr[i + 1], &arr[high]); // OPTIMIZATION: Swaps the pivot into its final sorted boundary position, bypassing if already there.
    return i + 1; // Returns the exact index where the pivot now resides, ensuring the array is partitioned correctly around it.
} // Ends the partition function.

void quickSort(int arr[], int low, int high) { // The main recursive Quick Sort implementation.
    if (low < high) { // Checks if the current array segment contains at least two elements, requiring further sorting.
        int pi = partition(arr, low, high); // Partitions the segment and retrieves the pivot's final, correctly sorted index.
        quickSort(arr, low, pi - 1); // Recursively invokes Quick Sort on the left sub-array (elements smaller than the pivot).
        quickSort(arr, pi + 1, high); // Recursively invokes Quick Sort on the right sub-array (elements greater than the pivot).
    } // Ends the base-case conditional check.
} // Ends the quickSort function.

/* ============================ UTILITIES ============================= */ // Visual separator and label for utility functions.
int *generateRandomArray(int n, unsigned int seed) { // Dynamically allocates and populates an array with pseudo-random numbers.
    int *arr = (int *)malloc(n * sizeof(int)); // Requests memory from the OS sufficient to hold 'n' integers.
    srand(seed); // Seeds the random number generator to ensure tests are identical across algorithms for fairness.
    for (int i = 0; i < n; i++) // Loops exactly 'n' times to populate every index of the newly created array.
        arr[i] = rand() % 1000000; // Assigns a random integer modulo 1,000,000 to prevent overflow and maintain readability.
    return arr; // Returns the memory pointer of the populated array to the caller.
} // Ends the generateRandomArray function.

int *copyArray(int arr[], int n) { // Creates an exact duplicate of a given array so algorithms can be tested on identical data.
    int *copy = (int *)malloc(n * sizeof(int)); // Allocates dynamic memory matching the size of the original array.
    memcpy(copy, arr, n * sizeof(int)); // Copies raw byte data directly from the original array to the copy very rapidly.
    return copy; // Returns the memory pointer of the copied array back to the caller.
} // Ends the copyArray function.

int isSorted(int arr[], int n) { // Verifies algorithm correctness by ensuring the array is strictly in ascending order.
    for (int i = 1; i < n; i++) // Loops starting from the second element up to the very last element.
        if (arr[i - 1] > arr[i]) return 0; // If any previous element is larger than the current, sorting failed, returns false (0).
    return 1; // If the loop completes without triggering the if-statement, the array is perfectly sorted, returns true (1).
} // Ends the isSorted validation function.

/* ============================== MAIN ================================ */ // Visual separator marking the program's entry point.
int main(void) { // The main function executed when the program launches.
    int sizes[10] = {1000, 2000, 5000, 10000, 20000, // Initializes an array containing the specific dataset sizes to benchmark.
                     50000, 100000, 200000, 500000, 1000000}; // Completes the initialization of the sizes array.
    int numTests = 10; // Declares a variable holding the total number of tests (matching the array length).

    FILE *fp = fopen("results.csv", "w"); // Opens (or creates) a CSV file in write mode to store benchmark data.
    if (!fp) { // Checks if the file pointer is null, which indicates an error opening the file (e.g., permission denied).
        fprintf(stderr, "Error opening results.csv for writing\n"); // Prints an error message to the standard error stream.
        return 1; // Terminates the program prematurely returning an error code.
    } // Ends the file-open error checking block.
    
    fprintf(fp, "Size,Merge_Ticks,Merge_Seconds,Merge_Comps,Merge_Swaps,Merge_Time_Const,Merge_Comp_Const," // Writes the CSV header row for Merge Sort metrics.
                "Heap_Ticks,Heap_Seconds,Heap_Comps,Heap_Swaps,Heap_Time_Const,Heap_Comp_Const," // Continues the CSV header row for Heap Sort metrics.
                "Quick_Ticks,Quick_Seconds,Quick_Comps,Quick_Swaps,Quick_Time_Const,Quick_Comp_Const\n"); // Completes the CSV header row with Quick Sort metrics and a newline.

    for (int t = 0; t < numTests; t++) { // Loops through every test size defined in the 'sizes' array.
        int n = sizes[t]; // Extracts the specific array size for the current benchmark iteration.
        int *original = generateRandomArray(n, 42 + t); // Generates a fresh random array for this size using a deterministic seed.

        int *arrM = copyArray(original, n); // Creates a dedicated copy of the random array specifically for Merge Sort to process.
        int *arrH = copyArray(original, n); // Creates a dedicated copy of the random array specifically for Heap Sort to process.
        int *arrQ = copyArray(original, n); // Creates a dedicated copy of the random array specifically for Quick Sort to process.
        clock_t start, end; // Declares variables to track CPU clock cycles before and after sorting.
        double nlogn = (double)n * log2((double)n); // Calculates the mathematical N*log2(N) complexity baseline used to derive the constant factors.

        /* --- Benchmark Merge Sort --- */ // Visual indicator for the start of Merge Sort benchmarking.
        current_comps = 0; current_swaps = 0; // Resets the global comparison and swap counters to zero for a clean test.
        start = clock(); // Records the exact CPU clock tick prior to invoking the sorting function.
        mergeSort(arrM, 0, n - 1); // Executes the optimized Merge Sort on its dedicated array copy.
        end = clock(); // Records the exact CPU clock tick immediately after the sorting finishes.
        clock_t m_ticks = end - start; // Subtracts the start ticks from the end ticks to find total elapsed CPU cycles.
        double m_secs = (double)m_ticks / CLOCKS_PER_SEC; // Converts raw CPU ticks into readable seconds.
        unsigned long long m_comps = current_comps; // Stores the final tracked comparisons into a local variable for Merge Sort.
        unsigned long long m_swaps = current_swaps; // Stores the final tracked swaps/writes into a local variable.
        double m_time_const = m_secs / nlogn; // Calculates the Empirical Time Constant (Time / (N log N)).
        double m_comp_const = (double)m_comps / nlogn; // Calculates the Mathematical Operations Constant (Comparisons / (N log N)).

        /* --- Benchmark Heap Sort --- */ // Visual indicator for the start of Heap Sort benchmarking.
        current_comps = 0; current_swaps = 0; // Clears the global trackers again to ensure Heap Sort's metrics are isolated.
        start = clock(); // Logs the starting CPU tick.
        heapSort(arrH, n); // Executes the optimized iterative Heap Sort on its dedicated array copy.
        end = clock(); // Logs the ending CPU tick.
        clock_t h_ticks = end - start; // Calculates total CPU cycles spent in Heap Sort.
        double h_secs = (double)h_ticks / CLOCKS_PER_SEC; // Converts the Heap Sort CPU cycles to seconds.
        unsigned long long h_comps = current_comps; // Saves the local comparison count for Heap Sort.
        unsigned long long h_swaps = current_swaps; // Saves the local swap count for Heap Sort.
        double h_time_const = h_secs / nlogn; // Calculates Heap Sort's Time Constant factor.
        double h_comp_const = (double)h_comps / nlogn; // Calculates Heap Sort's Comparison Constant factor.

        /* --- Benchmark Quick Sort --- */ // Visual indicator for the start of Quick Sort benchmarking.
        current_comps = 0; current_swaps = 0; // Zeros out global variables once more for the final algorithm benchmark.
        start = clock(); // Records start time.
        quickSort(arrQ, 0, n - 1); // Executes the optimized Quick Sort on its dedicated array copy.
        end = clock(); // Records end time.
        clock_t q_ticks = end - start; // Determines the total elapsed CPU ticks for Quick Sort.
        double q_secs = (double)q_ticks / CLOCKS_PER_SEC; // Formats ticks to standard seconds.
        unsigned long long q_comps = current_comps; // Captures Quick Sort's total array comparisons.
        unsigned long long q_swaps = current_swaps; // Captures Quick Sort's total array swaps.
        double q_time_const = q_secs / nlogn; // Derives the Time Constant specific to Quick Sort.
        double q_comp_const = (double)q_comps / nlogn; // Derives the mathematical Comparison Constant for Quick Sort.

        /* --- Integrity Checks --- */ // Visual indicator for the verification step.
        if (!isSorted(arrM, n)) fprintf(stderr, "ERROR: MergeSort failed at n=%d\n", n); // Prints an error if Merge Sort failed to correctly sort the data.
        if (!isSorted(arrH, n)) fprintf(stderr, "ERROR: HeapSort failed at n=%d\n", n); // Prints an error if Heap Sort failed to correctly sort the data.
        if (!isSorted(arrQ, n)) fprintf(stderr, "ERROR: QuickSort failed at n=%d\n", n); // Prints an error if Quick Sort failed to correctly sort the data.

        /* --- Console Output --- */ // Visual indicator for outputting results to the terminal.
        printf("[ Array Size: %-7d ]\n", n); // Prints the current array size being tested in a clearly formatted header.
        printf("  Merge Sort | Sec: %-8.6f | Comps: %-10llu | C-Const: %-8.4f | T-Const: %.2e\n", // Prints Merge Sort statistics, including the calculated constants.
               m_secs, m_comps, m_comp_const, m_time_const); // Injects the corresponding variables into the printf statement.
        printf("  Heap Sort  | Sec: %-8.6f | Comps: %-10llu | C-Const: %-8.4f | T-Const: %.2e\n", // Prints Heap Sort statistics cleanly aligned.
               h_secs, h_comps, h_comp_const, h_time_const); // Feeds Heap variables into the string formatters.
        printf("  Quick Sort | Sec: %-8.6f | Comps: %-10llu | C-Const: %-8.4f | T-Const: %.2e\n", // Outputs the final Quick Sort stats.
               q_secs, q_comps, q_comp_const, q_time_const); // Feeds Quick variables.
        printf("--------------------------------------------------------------------------------\n"); // Prints a separator line for visual clarity between sizes in the terminal.

        /* --- Write to CSV --- */ // Visual indicator for file writing logic.
        fprintf(fp, "%d,%ld,%.6f,%llu,%llu,%.10e,%.6f,%ld,%.6f,%llu,%llu,%.10e,%.6f,%ld,%.6f,%llu,%llu,%.10e,%.6f\n", // Writes the massive formatted string representing one full row of CSV data.
                n, // Outputs array size (Column 1).
                m_ticks, m_secs, m_comps, m_swaps, m_time_const, m_comp_const, // Outputs the 6 columns specific to Merge Sort.
                h_ticks, h_secs, h_comps, h_swaps, h_time_const, h_comp_const, // Outputs the 6 columns specific to Heap Sort.
                q_ticks, q_secs, q_comps, q_swaps, q_time_const, q_comp_const); // Outputs the 6 columns specific to Quick Sort.

        free(original); // Frees the base random array memory back to the system to prevent exhaustion across test iterations.
        free(arrM); // Frees the memory for the Merge Sort copy.
        free(arrH); // Frees the memory for the Heap Sort copy.
        free(arrQ); // Frees the memory for the Quick Sort copy, completing cleanup for this loop cycle.
    } // Ends the main loop evaluating each array size.

    fclose(fp); // Closes the results.csv file, flushing pending writes and unlocking it for the Python script.
    printf("\nDetailed results with swaps, comparisons, and constants written to results.csv\n"); // Notifies the user the program finished gracefully and data is ready.
    return 0; // Signals to the OS that the C program executed successfully without crashes.
} // Closes the main function block, ending the C code file.
