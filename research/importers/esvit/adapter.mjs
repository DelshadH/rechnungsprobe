import { UblReader } from "einvoicing";

const invoice = await new UblReader().readFromFile("/input/invoice.xml");
process.stdout.write(JSON.stringify({
  accepted: true,
  invoice: JSON.parse(JSON.stringify(invoice)),
}) + "\n");
