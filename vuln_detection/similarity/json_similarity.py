import json
from bs4 import BeautifulSoup
from config import vuln_scan_config


def load_json_file(file_path):
    """
    Loads a JSON file from the specified file path.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The parsed JSON data as a Python dictionary.

    Raises:
        FileNotFoundError: If the file does not exist.
        JSONDecodeError: If the file content is not valid JSON.
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)


def replace_json_values(s):
    """
    Replaces JSON-style values with Python-style values.

    Args:
        s (str): The JSON string to replace values in.

    Returns:
        str: The modified string with 'null', 'true', 'false' replaced by 'None', 'True', 'False'.
    """
    s = s.replace('null', 'None')
    s = s.replace('true', 'True')
    s = s.replace('false', 'False')
    return s


def flatten_json(y):
    """
    Flattens a nested JSON object into a single level dictionary.

    Args:
        y (dict or list): The JSON object to flatten.

    Returns:
        dict: A flattened dictionary with keys representing the full paths of nested elements.
    """
    out = {}

    def flatten(x, name=''):
        """
        Helper function to recursively flatten a nested object.

        Args:
            x (dict, list, or primitive): The current data element being processed.
            name (str): The accumulated key/path for the current element.
        """
        if type(x) is dict:
            for k, v in x.items():
                new_name = f"{name}{k}" if name else k
                flatten(v, new_name)
        elif type(x) is list:
            for i, v in enumerate(x):
                new_name = f"{name}{i}" if name else str(i)
                flatten(v, new_name)
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def calculate_json_similarity(json1_str, json2_str):
    """
    Calculates the similarity between two JSON objects based on their flattened structure.

    Args:
        json1_str (str): The first JSON string.
        json2_str (str): The second JSON string.

    Returns:
        float: A similarity score between 0 and 1, where 1 indicates identical JSONs.
               Returns 0 if no common keys are found.
    """
    json1 = json.loads(json1_str)
    json2 = json.loads(json2_str)
    flat_json1 = flatten_json(json1)
    flat_json2 = flatten_json(json2)
    keys1 = set(flat_json1.keys())
    keys2 = set(flat_json2.keys())
    intersection = keys1.intersection(keys2)
    union = keys1.union(keys2)

    if not intersection:
        return 0

    similarity_score = len(intersection) / len(union)

    # Iterate through the intersection and calculate deeper similarity
    for key in intersection:
        if isinstance(flat_json1[key], dict) and isinstance(flat_json2[key], dict):
            sub_similarity = calculate_json_similarity(flat_json1[key], flat_json2[key])
            similarity_score *= sub_similarity
        else:
            if flat_json1[key] != flat_json2[key]:
                similarity_score *= vuln_scan_config.JSON_SIMILARITY_MISMATCH_PENALTY

    return similarity_score


def is_valid_json(json_str, expected_type=dict):
    """
    Checks if a string is a valid JSON and optionally checks its type.

    Args:
        json_str (str): The string to check.
        expected_type (type, optional): The expected type of the parsed JSON object (e.g., dict, list).

    Returns:
        bool: True if the string is a valid JSON and matches the expected type, False otherwise.
    """
    if not json_str:  # Handle empty string or None
        return False
    try:
        parsed_data = json.loads(json_str)

        # If expected_type is provided, check if the parsed data matches the expected type
        if expected_type is not None:
            if not isinstance(parsed_data, expected_type):
                return False
        return True
    except json.JSONDecodeError:
        return False
    except Exception:
        # Catch any other unforeseen errors
        return False


def get_json_similarity(data1, data2):
    """
    Extracts text from the 'body' of HTML or plain data, checks if both data are valid JSON,
    and calculates their similarity.

    Args:
        data1 (str): The first data to compare, either as HTML or plain text.
        data2 (str): The second data to compare, either as HTML or plain text.

    Returns:
        bool: True if both data are valid JSON and their similarity exceeds the threshold,
              False otherwise.
    """
    if "body" in data1:
        soup = BeautifulSoup(data1, 'html.parser')
        matches1 = soup.find('body').get_text()
    else:
        matches1 = data1

    if "body" in data2:
        soup = BeautifulSoup(data2, 'html.parser')
        matches2 = soup.find('body').get_text()
    else:
        matches2 = data2

    if is_valid_json(matches1) and is_valid_json(matches2):
        json_similarity_threshold = vuln_scan_config.JSON_SIMILARITY_THRESHOLD
        similarity = calculate_json_similarity(matches1, matches2)
        if similarity > json_similarity_threshold:
            return True
    return False
