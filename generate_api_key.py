import secrets
import string

def generate_api_key(length: int = 32) -> str:
    """
    Generates a random API key.
    
    Args:
        length (int): The length of the API key. Default is 32.
    
    Returns:
        str: A securely generated random API key.
    """
    # Characters to use in the API key
    characters = string.ascii_letters + string.digits + string.punctuation
    
    # Securely generate the API key
    api_key = ''.join(secrets.choice(characters) for _ in range(length))
    
    return api_key

# Example usage
new_api_key = generate_api_key(32)
print(f"Generated API Key: {new_api_key}")
