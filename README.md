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
