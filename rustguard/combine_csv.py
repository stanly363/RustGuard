import pandas as pd

def combine_all_data(file_one='final.csv', 
                     file_two='benign_flows_40MB.csv', 
                     output_file='combined_all_flows.csv'):
    """
    Combines every row from two CSV files into a single output file.
    """
    try:
        # 1. Load both CSV files
        print(f"Loading all data from '{file_one}'...")
        df_one = pd.read_csv(file_one)
        
        print(f"Loading all data from '{file_two}'...")
        df_two = pd.read_csv(file_two)
        
    except FileNotFoundError as e:
        print(f"Error: Could not find a required file. {e}")
        return

    # 2. Combine the two full datasets
    print("Combining all flows from both files...")
    final_df = pd.concat([df_one, df_two], ignore_index=True)

    # 3. Shuffle the final dataset to mix the rows randomly
    print("Shuffling the final dataset...")
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 4. Save the result to a new CSV file
    final_df.to_csv(output_file, index=False)
    
    print(f"\nSuccessfully created '{output_file}'.")
    print("\n--- Final Dataset Distribution ---")
    print(final_df['Label'].value_counts())
    print("----------------------------------")
    print(f"Total flows in the final dataset: {len(final_df)}")

# --- Main execution ---
if __name__ == "__main__":
    combine_all_data()