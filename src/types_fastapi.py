"""FastAPI types"""

dictionary = {'name': 'John', 'age': 3, 'is_cowboy': True}


def get_full_name(first_name: str, last_name: str) -> str:
    full_name = first_name.lower() + ' ' + last_name.title()
    return full_name


def get_name_age(first_name: str, last_name: str, age: int) -> str:
    age_statement = (
        f'My name is {get_full_name(first_name, last_name)} and I am {age} years old.'
    )
    return age_statement


# * Those internal types in the square brackets are called 'type parameters'
def process_items(item: list[str]):
    counter: int = 0
    for i in item:
        counter += 1
        print(f'item {counter}: {i.title()}')


def process_dictionary(data: dict[str, int | str]) -> str:
    result: list = []
    for key, value in data.items():
        result.append(f'{key}: {value}')
    return '\n'.join(result)


# print(get_full_name('John', 'dutton'))
# print(get_name_age('John', 'dutton', 3))
# print(process_items(['John', 'Dutton', 'is', 'a', 'cowboy', '3']))
# print(process_dictionary(dictionary))

# * Classes as types


class Animal:
    def __init__(self, name: str):
        self.name = name


def get_animal_name(animal: Animal):
    return animal
