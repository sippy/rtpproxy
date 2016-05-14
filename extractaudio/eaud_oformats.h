struct supported_fmt {
    const char *name;
    uint32_t id;
    const char *descr;
};

extern const struct supported_fmt eaud_file_fmts[];
extern const struct supported_fmt eaud_data_fmts[];
extern const struct supported_fmt eaud_data_ends[];

const struct supported_fmt *pick_format(const char *,
  const struct supported_fmt []);
void dump_formats_descr(const char *,
  const struct supported_fmt[]);

