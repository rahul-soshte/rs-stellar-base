use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Sets, modifies, or deletes a data entry (name/value pair) that is attached to an account
    ///
    /// Threshold: Medium
    pub fn manage_data(
        &self,
        name: &str,
        data: Option<&Vec<u8>>,
    ) -> Result<xdr::Operation, operation::Error> {
        //

        let data_name = xdr::String64(
            name.try_into()
                .map_err(|_| operation::Error::InvalidField("name".into()))?,
        );
        let data_value: Option<xdr::DataValue> = match data {
            Some(value) => {
                let bytes = value
                    .try_into()
                    .map_err(|_| operation::Error::InvalidField("data".into()))?;
                Some(xdr::DataValue(bytes))
            }
            None => None,
        };

        let body = xdr::OperationBody::ManageData(xdr::ManageDataOp {
            data_name,
            data_value,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_manage_data() {
        let name = "Saved Data";
        let data = "Important data to be saved";
        let op = Operation::new()
            .manage_data(name, Some(&data.as_bytes().to_vec()))
            .unwrap();

        if let xdr::OperationBody::ManageData(xdr::ManageDataOp {
            data_name,
            data_value: Some(value),
        }) = op.body
        {
            assert_eq!(data_name.as_vec(), &name.as_bytes().to_vec());
            assert_eq!(value.to_vec(), data.as_bytes().to_vec());
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_manage_data_delete_entry() {
        let name = "Saved Data";
        let op = Operation::new().manage_data(name, None).unwrap();

        if let xdr::OperationBody::ManageData(xdr::ManageDataOp {
            data_name,
            data_value,
        }) = op.body
        {
            assert_eq!(data_name.as_vec(), &name.as_bytes().to_vec());
            assert_eq!(data_value, None);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_manage_data_long_name_64() {
        let name = std::str::from_utf8([65; 64].as_slice()).unwrap(); // 64 letter 'A'
        let data = "Important data to be saved";
        let op = Operation::new().manage_data(name, Some(&data.as_bytes().to_vec()));

        assert!(op.is_ok());
    }
    #[test]
    fn test_manage_data_too_long_name() {
        let name = std::str::from_utf8([65; 65].as_slice()).unwrap(); // 65 letter 'A'
        let data = "Important data to be saved";
        let op = Operation::new().manage_data(name, Some(&data.as_bytes().to_vec()));

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("name".into()))
        );
    }
    #[test]
    fn test_manage_data_long_data_64() {
        let name = "Data name";
        let data = std::str::from_utf8([65; 64].as_slice()).unwrap(); // 64 letter 'A'
        let op = Operation::new().manage_data(name, Some(&data.as_bytes().to_vec()));

        assert!(op.is_ok());
    }
    #[test]
    fn test_manage_data_too_long_data() {
        let name = "Data name";
        let data = std::str::from_utf8([65; 65].as_slice()).unwrap(); // 65 letter 'A'
        let op = Operation::new().manage_data(name, Some(&data.as_bytes().to_vec()));

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("data".into()))
        );
    }
}
