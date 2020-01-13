#### Run Command
1. Install requirements: pip install -r requirements.txt
2. Run: python main.py run


#### ES Indices

PUT pms_users/_mapping/user
{
  "dynamic": "strict",
  "properties": {
    "username": {
        "type": "text"
    },
    "password": {
        "type": "text"
    },
    "fullname": {
        "type": "text"
    },
    "email": {
        "type": "text"
    },
    "phone": {
        "type": "text"
    },
    "designation": {
        "type": "text"
    },
    "date_of_birth": {
        "type": "date"
    },
    "gender": {
        "type": "text"
    },
    "nid": {
        "type": "text"
    },
    "role": {
        "type": "text"
    },
    "user_role": {
        "type": "text"
    },
    "user_type": {
        "type": "text"
    },
    "address": {
        "type": "text"
    },
    "department": {
        "type": "text"
    },
    "status": {
        "type": "keyword"
    },
    "notes": {
        "type": "text"
    },
    "created_at": {
        "type": "long"
    },
    "created_by": {
        "type": "text"
    },
    "updated_at": {
        "type": "long"
    },
    "updated_by": {
        "type": "text"
    }
  }
}


PUT pms_projects/_mapping/project
{
  "dynamic": "strict",
  "properties": {
    "project_name": {
        "type": "text"
    },
    "commencement_date": {
        "type": "long"
    },
    "termination_date": {
        "type": "long"
    },
    "project_value": {
        "type": "text"
    },
    "description": {
        "type": "text"
    },
    "notes": {
        "type": "text"
    },
    "status": {
        "type": "text"
    },
    "created_at": {
        "type": "long"
    },
    "created_by": {
        "type": "text"
    },
    "updated_at": {
        "type": "long"
    },
    "updated_by": {
        "type": "text"
    }
  }
}


PUT pms_transactions/_mapping/transaction
{
  "dynamic": "strict",
  "properties": {
    "transaction_id": {
        "type": "keyword"
    },
    "payment_date": {
        "type": "long"
    },
    "payment_by": {
        "type": "keyword"
    },
    "project_id": {
        "type": "keyword"
    },
    "mode_of_payment": {
        "type": "text"
    },
    "voucher_no": {
        "type": "keyword"
    },
    "amount": {
        "type": "double"
    },
    "currency": {
        "type": "keyword"
    },
    "status": {
        "type": "text"
    },
    "remarks": {
        "type": "text"
    },
    "cheque_no": {
        "type": "keyword"
    },
    "description": {
        "type": "text"
    },
    "created_at": {
        "type": "long"
    },
    "created_by": {
        "type": "text"
    },
    "updated_at": {
        "type": "long"
    },
    "updated_by": {
        "type": "text"
    }
  }
}


PUT pms_bills/_mapping/bill
{
  "dynamic": "strict",
  "properties": {
    "bill_id": {
        "type": "keyword"
    },
    "submission_date": {
        "type": "long"
    },
    "project_id": {
        "type": "keyword"
    },
    "purpose": {
        "type": "text"
    },
    "amount": {
        "type": "double"
    },
    "currency": {
        "type": "keyword"
    },
    "status": {
        "type": "text"
    },
    "remarks": {
        "type": "text"
    },
    "description": {
        "type": "text"
    },
    "created_at": {
        "type": "long"
    },
    "created_by": {
        "type": "text"
    },
    "updated_at": {
        "type": "long"
    },
    "updated_by": {
        "type": "text"
    }
  }
}

PUT pms_user_role_lookup/_mapping/role
{
  "dynamic": "strict",
  "properties": {
    "created_at": {
      "type": "long"
    },
    "created_by": {
      "type": "keyword"
    },
    "edited_at": {
      "type": "long"
    },
    "edited_by": {
      "type": "keyword"
    },
    "id": {
      "type": "text",
      "fields": {
        "keyword": {
          "type": "keyword",
          "ignore_above": 256
        }
      }
    },
    "method_access": {
      "type": "nested",
      "properties": {
        "access_code": {
          "type": "keyword"
        },
        "access_name": {
          "type": "text"
        }
      }
    },
    "role_id": {
      "type": "keyword"
    },
    "role_level": {
      "type": "long"
    },
    "role_name": {
      "type": "text"
    },
    "updated_at": {
      "type": "long"
    },
    "updated_by": {
      "type": "text",
      "fields": {
        "keyword": {
          "type": "keyword",
          "ignore_above": 256
        }
      }
    }
  }
}


PUT pms_method_access_lookup/_mapping/access
{
  "dynamic": "strict",
  "properties": {
    "access_code": {
      "type": "keyword"
    },
    "access_group": {
      "type": "keyword"
    },
    "access_name": {
      "type": "text"
    }
  }
}


#### User Role With Access

{
  "role_name": "admin",
  "role_id": "0000",
  "role_level": "1",
  "method_access": [
    {
      "access_code": "ALL",
      "access_name": "ALL"
    },
    {
      "access_code": "DELETE_BILL",
      "access_name": "Delete Bill"
    },
    {
      "access_code": "DELETE_PROJECT",
      "access_name": "Delete Project"
    },
    {
      "access_code": "DELETE_LOOKUP",
      "access_name": "Delete Lookup"
    },
    {
      "access_code": "DELETE_USER",
      "access_name": "Delete User"
    },
    {
      "access_code": "SEARCH_BILL",
      "access_name": "Search Bill Entry"
    },
    {
      "access_code": "SEARCH_USER",
      "access_name": "Search User Entry"
    },
    {
      "access_code": "SEARCH_PROJECT",
      "access_name": "Search Project Entry"
    },
    {
      "access_code": "SEARCH_LOOKUP",
      "access_name": "Search Lookup Entry"
    },
    {
      "access_code": "CREATE_LOOKUP",
      "access_name": "Create Lookup Entry"
    },
    {
      "access_code": "CREATE_USER",
      "access_name": "Create User"
    },
    {
      "access_code": "CREATE_BILL",
      "access_name": "Create Bill"
    },
    {
      "access_code": "CREATE_PROJECT",
      "access_name": "Create Project"
    },
    {
      "access_code": "UPDATE_USER",
      "access_name": "Update User Details"
    },
    {
      "access_code": "UPDATE_BILL",
      "access_name": "Update Bill Details"
    },
    {
      "access_code": "UPDATE_PROJECT",
      "access_name": "Update Project Details"
    },
    {
      "access_code": "UPDATE_LOOKUP",
      "access_name": "Update Lookup Details"
    },
    {
      "access_code": "VIEW_USER",
      "access_name": "View User Details"
    },
    {
      "access_code": "VIEW_PROJECT",
      "access_name": "View Project Details"
    },
    {
      "access_code": "VIEW_BILL",
      "access_name": "View Bill Details"
    },
    {
      "access_code": "VIEW_LOOKUP",
      "access_name": "View Lookup Details"
    }
  ]
}