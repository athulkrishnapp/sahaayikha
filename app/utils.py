# app/utils.py

from math import radians, sin, cos, sqrt, atan2

# ... (Keep GEOCODE_DATA, geocode_location, haversine_distance as they are) ...
GEOCODE_DATA = {
    'Alappuzha': (9.4981, 76.3388),
    'Ernakulam': (9.9816, 76.2999),
    'Idukki': (9.8483, 76.9695),
    'Kannur': (11.8745, 75.3704),
    'Kasargod': (12.5123, 74.9876),
    'Kollam': (8.8932, 76.6141),
    'Kottayam': (9.5916, 76.5222),
    'Kozhikode': (11.2588, 75.7804),
    'Malappuram': (11.0538, 76.0736),
    'Palakkad': (10.7867, 76.6548),
    'Pathanamthitta': (9.2647, 76.7870),
    'Thiruvananthapuram': (8.5241, 76.9366),
    'Thrissur': (10.5276, 76.2144),
    'Wayanad': (11.6854, 76.1320),
}

def geocode_location(location_name):
    """
    Simulated geocoding function.
    Returns (latitude, longitude) for a given location name.
    """
    if not location_name:
        return None, None
    main_district = location_name.split(' - ')[0]
    coords = GEOCODE_DATA.get(main_district)
    return coords if coords else (None, None)

def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the distance between two points in kilometers
    using the Haversine formula.
    """
    if None in [lat1, lon1, lat2, lon2]: # Handle cases where coordinates might be missing
        return float('inf') # Return infinity if coords are missing

    R = 6371  # Radius of Earth in kilometers
    lat1_rad, lon1_rad, lat2_rad, lon2_rad = map(radians, [lat1, lon1, lat2, lon2])

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c
    return distance

# --- NEW FUNCTION ---
def get_keywords(text):
    """
    Extracts potential keywords from text by removing common stop words.
    Returns a set of lowercase words.
    """
    if not text:
        return set()

    stop_words = {
        'a', 'an', 'the', 'in', 'on', 'of', 'for', 'to', 'with', 'is', 'it', 'and',
        'or', 'i', 'you', 'he', 'she', 'we', 'they', 'item', 'good', 'condition',
        'was', 'are', 'be', 'been', 'has', 'had', 'do', 'does', 'did', 'will',
        'shall', 'should', 'can', 'could', 'may', 'might', 'must', 'about', 'above',
        'after', 'again', 'against', 'all', 'am', 'any', 'as', 'at', 'because',
        'before', 'below', 'between', 'both', 'but', 'by', 'down', 'during', 'each',
        'few', 'from', 'further', 'here', 'how', 'into', 'just', 'more', 'most',
        'my', 'no', 'nor', 'not', 'now', 'only', 'other', 'our', 'out', 'over',
        'own', 'same', 'so', 'some', 'such', 'than', 'that', 'then', 'there', 'these',
        'this', 'those', 'through', 'too', 'under', 'until', 'up', 'very', 'what',
        'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'your'
    }

    # Basic cleaning: remove punctuation and convert to lowercase
    cleaned_text = ''.join(c.lower() if c.isalnum() or c.isspace() else ' ' for c in text)
    words = cleaned_text.split()

    # Filter out stop words and short words
    return {word for word in words if word not in stop_words and len(word) > 2}