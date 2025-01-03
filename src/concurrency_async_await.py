"""Aseynchronous Code
Is a way to tell the computer / program that at some point in the future, it will have to wait for something to happen.
So, during that time, the coputer can go and do some other work instead of just waiting for that one thing to happen.
"""


async def get_burgers(number: int) -> int:
    # add tome async code here

    return number


print(get_burgers(5))  # <coroutine object get_burgers at
