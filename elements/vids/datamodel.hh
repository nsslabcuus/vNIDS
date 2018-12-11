#ifndef __CLICK_VIDS_DATAMODEL__
#define __CLICK_VIDS_DATAMODEL__

CLICK_DECLS

/** @brief Try to implement an event data parser by template
 *
 * Example of usage:
 *
 * typedef DataModelBuilder<EmptyModel> ::
 * FixedLengthField<HTTP_FIELD_VERSION, char, 7> :: Builder ::
 * VarLengthField<HTTP_FIELD_COOKIE, char> :: Builder ::
 * VarLengthField<HTTP_FIELD_USRAGENT, char> HttpDataModel;
 *
 * HttpDataModel model(buffer);
 *
 *
 * // some field can only be gotten by the field pointer, may be char*
 * get_field<HttpDataModel, HTTP_FIELD_USRAGENT>(model);
 * // some field can only be gotten by the field value, may be int, char, etc.
 * get_value<HttpDataModel, HTTP_FIELD_VERSION>(model);
 *
 */

/** @brief Field ID
 */
enum {
  HTTP_FIELD_VERSION,
  HTTP_FIELD_COOKIE,
  HTTP_FIELD_USRAGENT,
  DNS_FIELD_QNAME,
  DNS_FIELD_RECORD_IP
};

/** @brief Infer the actual field struct that I want to to use
 */

template <int FieldID, typename Model>
struct GetField;

template <int ExpectFID, int ActualFID, typename Model>
struct GetFieldHelper {
  typedef
      typename GetField<ExpectFID, typename Model::BaseModelType>::Field Field;
};

template <int ActualFID, typename Model>
struct GetFieldHelper<ActualFID, ActualFID, Model> {
  typedef Model Field;
};

template <int FieldID, typename Model>
struct GetField {
  typedef typename GetFieldHelper<FieldID, Model::ID, Model>::Field Field;
};

/**
 * getter function
 * function template partial specialization is not allowed, so make them in a
 * struct
 */
template <typename Model, int FieldID>
struct Getter;

template <typename Model, int ExpectFID, int ActualFID>
struct GetterHelper {
  static typename GetField<ExpectFID, Model>::Field::ReturnValueType *get(
      Model &m) {
    // recursing to BaseModel
    return Getter<typename Model::BaseModelType, ExpectFID>::get(m._model);
  }

  static typename GetField<ExpectFID, Model>::Field::ReturnValueType get_value(
      Model &m) {
    return Getter<typename Model::BaseModelType, ExpectFID>::get_value(
        m._model);
  }
};

template <typename Model, int ActualFID>
struct GetterHelper<Model, ActualFID, ActualFID> {
  /** @brief get pointer
   */
  static typename GetField<ActualFID, Model>::Field::ReturnValueType *get(
      Model &m) {
    size_t n = sizeof(typename Model::ReturnValueType) * m.field_len() + 1;
    typename Model::ReturnValueType *tmp =
        (typename Model::ReturnValueType *)malloc(n);
    memcpy(tmp, m._begin + Model::PADDING_SIZE, n);
    tmp[n - 1] = (typename Model::ReturnValueType)0;
    return tmp;
  }
  /** @brief get value
   */
  static typename Model::ReturnValueType get_value(Model &m) {
    return *(typename Model::ReturnValueType *)(m._begin + Model::PADDING_SIZE);
  }
};

template <typename Model, int FieldID>
struct Getter {
  static typename GetField<FieldID, Model>::Field::ReturnValueType *get(
      Model &m) {
    return GetterHelper<Model, FieldID, Model::ID>::get(m);
  }
  static typename GetField<FieldID, Model>::Field::ReturnValueType get_value(
      Model &m) {
    return GetterHelper<Model, FieldID, Model::ID>::get_value(m);
  }
};

// API for using pointer getter
template <typename Model, int FieldID>
typename GetField<FieldID, Model>::Field::ReturnValueType *get_field(Model &m) {
  return Getter<Model, FieldID>::get(m);
}

// API for using value getter
template <typename Model, int FieldID>
typename GetField<FieldID, Model>::Field::ReturnValueType get_value(Model &m) {
  return Getter<Model, FieldID>::get_value(m);
}

template <typename BaseModel>
struct DataModelBuilder {
  /** @brief fixed length field
   */
  template <int FID, typename DataT, int Len>
  struct FixedLengthField {
    enum { ID = FID, PADDING_SIZE = 0 };
    typedef DataModelBuilder<FixedLengthField> Builder;
    typedef BaseModel BaseModelType;
    typedef DataT ReturnValueType;

    FixedLengthField(char *buf)
        : _model(buf), _begin(_model._begin + _model.len()) {}

    inline size_t len() { return (size_t)(sizeof(DataT) * Len); }
    // @note: Must be validate before use
    inline bool validate(char *end) { return _begin + len() <= end; }

    BaseModel _model;
    char *_begin;
  };

  /** @brief variable length field
   * [uint32_t len][data...]
   */
  template <int FID, typename DataT>
  struct VarLengthField {
    enum { ID = FID, PADDING_SIZE = sizeof(uint32_t) };
    typedef DataModelBuilder<VarLengthField> Builder;
    typedef BaseModel BaseModelType;
    typedef DataT ReturnValueType;

    VarLengthField(char *buf)
        : _model(buf), _begin(_model._begin + _model.len()) {}

    inline size_t len() { return PADDING_SIZE + sizeof(DataT) * field_len(); }
    inline uint32_t field_len() { return *(uint32_t *)_begin; }
    // @note: Must be validate before use
    inline bool validate(char *end) { return _begin + len() <= end; }

    BaseModel _model;
    char *_begin;
  };
};

struct EmptyModel {
  enum { ID };
  typedef DataModelBuilder<EmptyModel> Builder;
  // @note !
  typedef EmptyModel BaseModelType;
  typedef void ReturnValueType;

  EmptyModel(char *buf) : _begin(buf) {}

  inline size_t len() { return 0; }

  char *_begin;
};

typedef DataModelBuilder<EmptyModel>::VarLengthField<HTTP_FIELD_COOKIE, char>::
    Builder ::VarLengthField<HTTP_FIELD_USRAGENT, char>
        HttpDataModel;

typedef DataModelBuilder<EmptyModel>::FixedLengthField<
    DNS_FIELD_RECORD_IP, uint32_t, 1>::Builder ::VarLengthField<DNS_FIELD_QNAME,
                                                                char>
    DNSDataModel;

CLICK_ENDDECLS

#endif
