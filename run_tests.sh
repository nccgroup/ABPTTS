#!/bin/bash
# Script to run tests using Poetry

# Run all tests
if [ "$1" == "" ]; then
    poetry run pytest
else
    # Run specific tests or with specific options
    poetry run pytest "$@"
fi