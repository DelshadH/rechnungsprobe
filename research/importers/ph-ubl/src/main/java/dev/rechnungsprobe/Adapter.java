package dev.rechnungsprobe;

import com.helger.ubl21.UBL21Marshaller;
import java.io.File;

public final class Adapter {
  private Adapter() {}

  public static void main(String[] args) {
    var invoice = UBL21Marshaller.invoice().read(new File("/input/invoice.xml"));
    if (invoice == null
        || UBL21Marshaller.invoice().write(invoice, new File("/output/roundtrip.xml")).isFailure()) {
      throw new IllegalStateException("UBL import or round-trip failed");
    }
  }
}
