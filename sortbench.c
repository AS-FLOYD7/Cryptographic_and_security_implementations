/*
 * sortbench.c
 * ------------------------------------------------------------------
 * Implements Merge Sort, Heap Sort and Quick Sort.
 * Benchmarks all three algorithms on 10 randomly generated arrays of
 * increasing size, measuring CPU time using clock() (raw clock ticks
 * and converted seconds via CLOCKS_PER_SEC).
 * Results are printed to stdout and written to results.csv for
 * plotting.
 * ------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

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
        if (L[i] <= R[j]) arr[k++] = L[i++];
        else arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];

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

    if (left < n && arr[left] > arr[largest]) largest = left;
    if (right < n && arr[right] > arr[largest]) largest = right;

    if (largest != i) {
        int temp = arr[i];
        arr[i] = arr[largest];
        arr[largest] = temp;
        heapify(arr, n, largest);
    }
}

void heapSort(int arr[], int n) {
    for (int i = n / 2 - 1; i >= 0; i--)
        heapify(arr, n, i);

    for (int i = n - 1; i > 0; i--) {
        int temp = arr[0];
        arr[0] = arr[i];
        arr[i] = temp;
        heapify(arr, i, 0);
    }
}

/* ============================ QUICK SORT ============================ */
void swap(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
}

/* median-of-three pivot selection keeps average performance good and
   avoids the classic O(n^2) worst case on sorted/reverse-sorted input */
int partition(int arr[], int low, int high) {
    int mid = low + (high - low) / 2;
    if (arr[mid] < arr[low])  swap(&arr[mid], &arr[low]);
    if (arr[high] < arr[low]) swap(&arr[high], &arr[low]);
    if (arr[high] < arr[mid]) swap(&arr[high], &arr[mid]);
    swap(&arr[mid], &arr[high]);

    int pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
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
    fprintf(fp, "Size,MergeSort_Ticks,MergeSort_Seconds,"
                "HeapSort_Ticks,HeapSort_Seconds,"
                "QuickSort_Ticks,QuickSort_Seconds\n");

    printf("%-10s %-16s %-16s %-16s %-12s %-12s %-12s\n",
           "Size", "Merge(ticks)", "Heap(ticks)", "Quick(ticks)",
           "Merge(s)", "Heap(s)", "Quick(s)");
    printf("---------------------------------------------------------------"
           "----------------------\n");

    for (int t = 0; t < numTests; t++) {
        int n = sizes[t];
        int *original = generateRandomArray(n, 42 + t);

        int *arrM = copyArray(original, n);
        int *arrH = copyArray(original, n);
        int *arrQ = copyArray(original, n);

        clock_t start, end;

        start = clock();
        mergeSort(arrM, 0, n - 1);
        end = clock();
        clock_t mergeTicks = end - start;
        double mergeSeconds = (double)mergeTicks / CLOCKS_PER_SEC;

        start = clock();
        heapSort(arrH, n);
        end = clock();
        clock_t heapTicks = end - start;
        double heapSeconds = (double)heapTicks / CLOCKS_PER_SEC;

        start = clock();
        quickSort(arrQ, 0, n - 1);
        end = clock();
        clock_t quickTicks = end - start;
        double quickSeconds = (double)quickTicks / CLOCKS_PER_SEC;

        if (!isSorted(arrM, n)) fprintf(stderr, "ERROR: MergeSort failed at n=%d\n", n);
        if (!isSorted(arrH, n)) fprintf(stderr, "ERROR: HeapSort failed at n=%d\n", n);
        if (!isSorted(arrQ, n)) fprintf(stderr, "ERROR: QuickSort failed at n=%d\n", n);

        printf("%-10d %-16ld %-16ld %-16ld %-12.6f %-12.6f %-12.6f\n",
               n, mergeTicks, heapTicks, quickTicks,
               mergeSeconds, heapSeconds, quickSeconds);

        fprintf(fp, "%d,%ld,%.6f,%ld,%.6f,%ld,%.6f\n",
                n, mergeTicks, mergeSeconds,
                heapTicks, heapSeconds,
                quickTicks, quickSeconds);

        free(original);
        free(arrM);
        free(arrH);
        free(arrQ);
    }

    fclose(fp);
    printf("\nResults written to results.csv\n");
    return 0;
}
