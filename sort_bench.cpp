/*
 * sortbench.c
 * ------------------------------------------------------------------
 * Implements Merge Sort, Heap Sort and Quick Sort.
 * Benchmarks algorithms on randomly generated arrays, measuring CPU time,
 * Number of Comparisons, and Number of Swaps/Writes.
 * Results are printed to stdout and written to results.csv for plotting.
 * ------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

/* Global counters for benchmarking */
unsigned long long current_comps = 0;
unsigned long long current_swaps = 0;

/* Unified swap function used by Quick Sort and Heap Sort */
void swap(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
    current_swaps++; // Track swap
}

/* ============================ MERGE SORT ============================ */
void merge(int arr[], int l, int m, int r) {
    int n1 = m - l + 1;
    int n2 = r - m;

    int *L = (int *)malloc(n1 * sizeof(int));
    int *R = (int *)malloc(n2 * sizeof(int));

    for (int i = 0; i < n1; i++) L[i] = arr[l + i];
    for (int j = 0; j < n2; j++) R[j] = arr[m + 1 + j];

    int i = 0, j = 0, k = l;
    while (i < n1 && j < n2) {
        current_comps++; // Track comparison
        if (L[i] <= R[j]) {
            arr[k++] = L[i++];
        } else {
            arr[k++] = R[j++];
        }
        current_swaps++; // Track array write (Merge Sort equivalent of a swap)
    }
    
    while (i < n1) { arr[k++] = L[i++]; current_swaps++; }
    while (j < n2) { arr[k++] = R[j++]; current_swaps++; }

    free(L);
    free(R);
}

void mergeSort(int arr[], int l, int r) {
    if (l < r) {
        int m = l + (r - l) / 2;
        mergeSort(arr, l, m);
        mergeSort(arr, m + 1, r);
        merge(arr, l, m, r);
    }
}

/* ============================ HEAP SORT ============================= */
void heapify(int arr[], int n, int i) {
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if (left < n) {
        current_comps++; // Track comparison
        if (arr[left] > arr[largest]) largest = left;
    }
    if (right < n) {
        current_comps++; // Track comparison
        if (arr[right] > arr[largest]) largest = right;
    }

    if (largest != i) {
        swap(&arr[i], &arr[largest]);
        heapify(arr, n, largest);
    }
}

void heapSort(int arr[], int n) {
    for (int i = n / 2 - 1; i >= 0; i--)
        heapify(arr, n, i);

    for (int i = n - 1; i > 0; i--) {
        swap(&arr[0], &arr[i]);
        heapify(arr, i, 0);
    }
}

/* ============================ QUICK SORT ============================ */
int partition(int arr[], int low, int high) {
    int mid = low + (high - low) / 2;
    
    // Median-of-three pivot selection tracking
    current_comps++; if (arr[mid] < arr[low])  swap(&arr[mid], &arr[low]);
    current_comps++; if (arr[high] < arr[low]) swap(&arr[high], &arr[low]);
    current_comps++; if (arr[high] < arr[mid]) swap(&arr[high], &arr[mid]);
    swap(&arr[mid], &arr[high]);

    int pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        current_comps++; // Track comparison
        if (arr[j] < pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return i + 1;
}

void quickSort(int arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}

/* ============================ UTILITIES ============================= */
int *generateRandomArray(int n, unsigned int seed) {
    int *arr = (int *)malloc(n * sizeof(int));
    srand(seed);
    for (int i = 0; i < n; i++)
        arr[i] = rand() % 1000000;
    return arr;
}

int *copyArray(int arr[], int n) {
    int *copy = (int *)malloc(n * sizeof(int));
    memcpy(copy, arr, n * sizeof(int));
    return copy;
}

int isSorted(int arr[], int n) {
    for (int i = 1; i < n; i++)
        if (arr[i - 1] > arr[i]) return 0;
    return 1;
}

/* ============================== MAIN ================================ */
int main(void) {
    int sizes[10] = {1000, 2000, 5000, 10000, 20000,
                      50000, 100000, 200000, 500000, 1000000};
    int numTests = 10;

    FILE *fp = fopen("results.csv", "w");
    if (!fp) {
        fprintf(stderr, "Error opening results.csv for writing\n");
        return 1;
    }
    
    // Write CSV Headers
    fprintf(fp, "Size,Merge_Ticks,Merge_Seconds,Merge_Comps,Merge_Swaps,"
                "Heap_Ticks,Heap_Seconds,Heap_Comps,Heap_Swaps,"
                "Quick_Ticks,Quick_Seconds,Quick_Comps,Quick_Swaps\n");

    for (int t = 0; t < numTests; t++) {
        int n = sizes[t];
        int *original = generateRandomArray(n, 42 + t);

        int *arrM = copyArray(original, n);
        int *arrH = copyArray(original, n);
        int *arrQ = copyArray(original, n);
        clock_t start, end;

        /* --- Benchmark Merge Sort --- */
        current_comps = 0; current_swaps = 0;
        start = clock();
        mergeSort(arrM, 0, n - 1);
        end = clock();
        clock_t m_ticks = end - start;
        double m_secs = (double)m_ticks / CLOCKS_PER_SEC;
        unsigned long long m_comps = current_comps;
        unsigned long long m_swaps = current_swaps;

        /* --- Benchmark Heap Sort --- */
        current_comps = 0; current_swaps = 0;
        start = clock();
        heapSort(arrH, n);
        end = clock();
        clock_t h_ticks = end - start;
        double h_secs = (double)h_ticks / CLOCKS_PER_SEC;
        unsigned long long h_comps = current_comps;
        unsigned long long h_swaps = current_swaps;

        /* --- Benchmark Quick Sort --- */
        current_comps = 0; current_swaps = 0;
        start = clock();
        quickSort(arrQ, 0, n - 1);
        end = clock();
        clock_t q_ticks = end - start;
        double q_secs = (double)q_ticks / CLOCKS_PER_SEC;
        unsigned long long q_comps = current_comps;
        unsigned long long q_swaps = current_swaps;

        /* --- Integrity Checks --- */
        if (!isSorted(arrM, n)) fprintf(stderr, "ERROR: MergeSort failed at n=%d\n", n);
        if (!isSorted(arrH, n)) fprintf(stderr, "ERROR: HeapSort failed at n=%d\n", n);
        if (!isSorted(arrQ, n)) fprintf(stderr, "ERROR: QuickSort failed at n=%d\n", n);

        /* --- Console Output --- */
        printf("[ Array Size: %-7d ]\n", n);
        printf("  Merge Sort | Ticks: %-6ld | Sec: %-8.6f | Comps: %-10llu | Writes: %llu\n", 
               m_ticks, m_secs, m_comps, m_swaps);
        printf("  Heap Sort  | Ticks: %-6ld | Sec: %-8.6f | Comps: %-10llu | Swaps : %llu\n", 
               h_ticks, h_secs, h_comps, h_swaps);
        printf("  Quick Sort | Ticks: %-6ld | Sec: %-8.6f | Comps: %-10llu | Swaps : %llu\n", 
               q_ticks, q_secs, q_comps, q_swaps);
        printf("--------------------------------------------------------------------------------\n");

        /* --- Write to CSV --- */
        fprintf(fp, "%d,%ld,%.6f,%llu,%llu,%ld,%.6f,%llu,%llu,%ld,%.6f,%llu,%llu\n",
                n, 
                m_ticks, m_secs, m_comps, m_swaps,
                h_ticks, h_secs, h_comps, h_swaps,
                q_ticks, q_secs, q_comps, q_swaps);

        free(original);
        free(arrM);
        free(arrH);
        free(arrQ);
    }

    fclose(fp);
    printf("\nDetailed results with swaps and comparisons written to results.csv\n");
    return 0;
}
