import pandas as pd
import random
from datetime import datetime

# Simulate a behavior-based dataset aligned with the project
def generate_behavior_dataset(samples_per_class=50):
    data = []
    for label in [0, 1]:  # 0 = Clean, 1 = Malicious
        for _ in range(samples_per_class):
            if label == 0:  # Clean behavior profile
                entry = {
                    "read_bytes": random.randint(5_000, 800_000),
                    "write_bytes": random.randint(1_000, 300_000),
                    "file_open_count": random.randint(2, 30),
                    "exe_run_attempts": random.randint(0, 1),
                    "cmd_proc_count": random.randint(0, 1),
                    "label": 0
                }
            else:  # Malicious behavior profile
                entry = {
                    "read_bytes": random.randint(1_000_000, 10_000_000),
                    "write_bytes": random.randint(300_000, 5_000_000),
                    "file_open_count": random.randint(30, 200),
                    "exe_run_attempts": random.randint(2, 10),
                    "cmd_proc_count": random.randint(1, 5),
                    "label": 1
                }
            data.append(entry)

    df = pd.DataFrame(data)
    df["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return df

# Create and save the dataset
dataset_df = generate_behavior_dataset()
dataset_path = "/mnt/data/behavior_ai_dataset.csv"
dataset_df.to_csv(dataset_path, index=False)
dataset_path
