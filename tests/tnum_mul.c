#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <json-c/json.h>
#include "tnum.h"

typedef struct {
    char method[64];
    double avg_time_ns;
    int correct_count;
    int total_count;
} MethodStats;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <rust_test_cases.json>\n", argv[0]);
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = "./tests/build/c_test_results.json";
    const int iterations = (argc > 2) ? atoi(argv[2]) : 1000;
    
    // 读取JSON文件
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        perror("Failed to open input file");
        return 1;
    }

    // 读取文件内容到缓冲区
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_str = (char *)malloc(file_size + 1);
    if (!json_str) {
        perror("Memory allocation failed");
        fclose(fp);
        return 1;
    }

    fread(json_str, 1, file_size, fp);
    json_str[file_size] = '\0';
    fclose(fp);

    // 解析JSON
    struct json_object *root_obj = json_tokener_parse(json_str);
    if (!root_obj) {
        fprintf(stderr, "Failed to parse JSON\n");
        free(json_str);
        return 1;
    }

    // 创建输出JSON数组
    struct json_object *output_array = json_object_new_array();
    
    // 统计信息
    MethodStats c_stats = {"C_tnum_mul", 0.0, 0, 0};

    int case_count = json_object_array_length(root_obj);
    printf("处理 %d 个测试用例...\n", case_count);

    for (int i = 0; i < case_count; i++) {
        struct json_object *test_case = json_object_array_get_idx(root_obj, i);
        
        // 获取输入
        struct json_object *input_a_obj, *input_b_obj;
        json_object_object_get_ex(test_case, "input_a", &input_a_obj);
        json_object_object_get_ex(test_case, "input_b", &input_b_obj);
        
        struct json_object *a_value_obj, *a_mask_obj, *b_value_obj, *b_mask_obj;
        json_object_object_get_ex(input_a_obj, "value", &a_value_obj);
        json_object_object_get_ex(input_a_obj, "mask", &a_mask_obj);
        json_object_object_get_ex(input_b_obj, "value", &b_value_obj);
        json_object_object_get_ex(input_b_obj, "mask", &b_mask_obj);
        
        // 从JSON解析为u64值
        uint64_t a_value = json_object_get_uint64(a_value_obj);
        uint64_t a_mask = json_object_get_uint64(a_mask_obj);
        uint64_t b_value = json_object_get_uint64(b_value_obj);
        uint64_t b_mask = json_object_get_uint64(b_mask_obj);

        // 创建C版本的tnum结构体
        struct tnum a = {.value = a_value, .mask = a_mask};
        struct tnum b = {.value = b_value, .mask = b_mask};
        
        struct json_object *results_obj;
        json_object_object_get_ex(test_case, "results", &results_obj);

        // 使用C版本的tnum_mul计算结果
        clock_t start = clock();
        // const int iterations = 1000; // 执行多次取平均以获得更准确的时间
        struct tnum c_result;
        
        for (int j = 0; j < iterations; j++) {
            c_result = tnum_mul(a, b);
        }
        
        clock_t end = clock();
        double time_taken_ns = ((double)(end - start)) / CLOCKS_PER_SEC * 1e9 / iterations;
        c_stats.avg_time_ns += time_taken_ns;
        c_stats.total_count++;

        // 将C版本的结果添加到test_case
        struct json_object *c_result_obj = json_object_new_object();
        json_object_object_add(c_result_obj, "method", json_object_new_string("C_tnum_mul"));
        
        struct json_object *c_output_obj = json_object_new_object();
        json_object_object_add(c_output_obj, "value", json_object_new_uint64(c_result.value));
        json_object_object_add(c_output_obj, "mask", json_object_new_uint64(c_result.mask));
        
        json_object_object_add(c_result_obj, "output", c_output_obj);
        json_object_object_add(c_result_obj, "avg_time_ns", json_object_new_double(time_taken_ns));

        // 将C的结果添加到results数组
        json_object_array_add(results_obj, c_result_obj);

        fflush(stdout);

        // 将修改后的test_case添加到输出数组
        json_object_array_add(output_array, json_object_get(test_case));
    }

    // 将结果写入文件
    const char *output_json = json_object_to_json_string_ext(output_array, JSON_C_TO_STRING_PRETTY);
    FILE *out_fp = fopen(output_file, "w");
    if (out_fp) {
        fputs(output_json, out_fp);
        fclose(out_fp);
        printf("\n结果已保存到：%s\n", output_file);
    } else {
        perror("Failed to open output file");
    }

    // 清理资源
    json_object_put(root_obj);
    json_object_put(output_array);
    free(json_str);

    return 0;
}