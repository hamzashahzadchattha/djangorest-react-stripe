# Django and React Authentication with JWT and Stripe payment

The project consists of two directories: 

- `client`: Contains the React application
- `server`: Contains the Django backend

## Installation

To run this project on your local machine, follow the steps below:

### Prerequisites

Ensure you have the following installed on your local machine:

- Python 3.8 or higher
- Node.js v14.15.0 or higher
- npm 6.14.9 or higher

### Setup

1. Clone the repository:
    ```
    git clone https://github.com/<yourusername>/<yourrepository>.git
    ```
2. Change into the directory:
    ```
    cd <yourrepository>
    ```

### Server

1. Navigate to the `server` directory:
    ```
    cd server
    ```
2. Install Django and other dependencies:
    ```
    pip install -r requirements.txt
    ```
3. Create a virtual environment (Optional but recommended):
    ```
    python -m venv env
    ```
4. Activate the virtual environment:
    On Windows:
    ```
    .\env\Scripts\activate
    ```
    On MacOS/Linux:
    ```
    source env/bin/activate
    ```
5. Create a `.env` file in the `server/core` directory and add stripe secret key and prices (copy from .env.example)

### Client

1. Navigate to the `client` directory:
    ```
    cd ../client
    ```
2. Install all the dependencies:
    ```
    npm install
    ```
3. Create `index.js` in `client/src/config` directory and add stripe key and prices (copy from index.js.example)
4. Run the client:
    ```
    npm start
    ```

Now, your application should be running at `localhost:3000`.

Note:
- The Django server should be running at the same time as the React application for the system to function properly.
- The application uses the email field instead of the username field for user identification.


# Task
- Clone this project to your local and Run this project successfully
- Review how the frontend and stripe subscriptions are working
- Add Swagger or Redoc API documentation for Django restful API endpoints (Write down well-organized and well-documented API reference)
- Create a new repository to your personal git and commit the result.

# Django REST Project Documentation

## Swagger Documentation Using `drf_yasg`

To provide a comprehensive and interactive API documentation, I used `drf_yasg`. Below is the process to set up and use `drf_yasg` for generating Swagger documentation.

## Below is POSTMAN Api collection and Environmental Variables For This Project.
 
### API Collection
  https://api.postman.com/collections/35060703-ebd9206f-b491-45ad-918e-5487ee9cc76b?access_key=PMAT-01J0157EFM9C31BTKYQFXDS1N3

### Environment


    {
	"id": "ea9da2ad-f7fe-4455-899c-e92c6c4b7641",
	"name": "django_subscription_app_env_local",
	"values": [
		{
			"key": "Base_URL",
			"value": "http://127.0.0.1:8000",
			"type": "default",
			"enabled": true
		},
		{
			"key": "AccessToekn",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "RefreshToken",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "CsrfToken",
			"value": "",
			"type": "default",
			"enabled": true
		},
		{
			"key": "X-CSRFToken",
			"value": "",
			"type": "default",
			"enabled": true
		}
	],
	"_postman_variable_scope": "environment",
	"_postman_exported_at": "2024-06-10T13:27:01.780Z",
	"_postman_exported_using": "Postman/11.1.25"
}

