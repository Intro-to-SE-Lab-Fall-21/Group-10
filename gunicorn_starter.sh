#!/bin/sh

gunicorn --chdir app app:app -w 2 --threads 2