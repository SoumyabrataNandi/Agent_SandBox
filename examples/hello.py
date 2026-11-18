import statistics, json
nums = [3, 1, 4, 1, 5, 9, 2, 6]
print(json.dumps({"mean": statistics.mean(nums), "median": statistics.median(nums)}))
