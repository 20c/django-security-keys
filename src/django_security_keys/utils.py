def convert_to_bool(data: bool) -> bool:
    if data is None:
        return False

    if isinstance(data, bool):
        return data

    if isinstance(data, str):
        return data.lower() == "true"

    return False
